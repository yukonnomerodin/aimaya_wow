param(
    [string]$PerfGateScriptPath = "scripts/run_world_probe_perf_gate.ps1",
    [string]$StartGatewaysScriptPath = "scripts/start_retail_gateways.ps1",
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_scale_profiles.latest.json",
    [string]$HypothesisId = "",
    [int]$IterationsPerProfile = 16,
    [int]$AllowFailuresPerProfile = -1,
    [switch]$AutoStartGateways,
    [string]$Profiles = "1,4,8,16,32",
    [int]$P50GateP1 = 420,
    [int]$P95GateP1 = 450,
    [int]$MaxGateP1 = 620,
    [double]$MaxFailureRatePctP1 = 8.0,
    [int]$P50GateP4 = 500,
    [int]$P95GateP4 = 560,
    [int]$MaxGateP4 = 700,
    [double]$MaxFailureRatePctP4 = 10.0,
    [int]$P50GateP8 = 700,
    [int]$P95GateP8 = 670,
    [int]$MaxGateP8 = 700,
    [double]$MaxFailureRatePctP8 = 15.0,
    [int]$P50GateP16 = 1100,
    [int]$P95GateP16 = 1200,
    [int]$MaxGateP16 = 1300,
    [double]$MaxFailureRatePctP16 = 24.0,
    [int]$P50GateP32 = 1500,
    [int]$P95GateP32 = 1100,
    [int]$MaxGateP32 = 1200,
    [double]$MaxFailureRatePctP32 = 28.0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param([string]$PathValue)

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::GetFullPath($PathValue)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $PathValue))
}

function Resolve-ProfileList {
    param([string]$ProfilesCsv)

    $profiles = $ProfilesCsv.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object { [int]$_.Trim() } |
        Select-Object -Unique

    if ($profiles.Count -eq 0) {
        throw "Profiles list is empty."
    }

    foreach ($p in $profiles) {
        if ($p -le 0) { throw "Profile parallelism must be > 0: $p" }
    }

    return [int[]]$profiles
}

function Get-GatesForParallelism {
    param([int]$Parallelism)

    switch ($Parallelism) {
        1 {
            return [PSCustomObject]@{ p50 = $P50GateP1; p95 = $P95GateP1; max = $MaxGateP1; failure_rate_pct = $MaxFailureRatePctP1 }
        }
        4 {
            return [PSCustomObject]@{ p50 = $P50GateP4; p95 = $P95GateP4; max = $MaxGateP4; failure_rate_pct = $MaxFailureRatePctP4 }
        }
        8 {
            return [PSCustomObject]@{ p50 = $P50GateP8; p95 = $P95GateP8; max = $MaxGateP8; failure_rate_pct = $MaxFailureRatePctP8 }
        }
        16 {
            return [PSCustomObject]@{ p50 = $P50GateP16; p95 = $P95GateP16; max = $MaxGateP16; failure_rate_pct = $MaxFailureRatePctP16 }
        }
        32 {
            return [PSCustomObject]@{ p50 = $P50GateP32; p95 = $P95GateP32; max = $MaxGateP32; failure_rate_pct = $MaxFailureRatePctP32 }
        }
        default {
            throw "No gate configured for parallelism=$Parallelism. Supported defaults: 1,4,8,16,32."
        }
    }
}

function Resolve-AllowFailuresForProfile {
    param(
        [int]$TargetIterations,
        [double]$GateFailureRatePercent,
        [int]$ExplicitAllowFailures
    )

    if ($ExplicitAllowFailures -ge 0) {
        return $ExplicitAllowFailures
    }

    if ($GateFailureRatePercent -le 0) {
        return 0
    }

    if ($GateFailureRatePercent -ge 100) {
        return [Math]::Max(0, $TargetIterations)
    }

    # Max failures that still allow reaching target successful probes while staying within failure-rate gate:
    # F / (S + F) <= r  =>  F <= (r * S) / (1 - r), where r is fraction.
    $maxFailures = [int][Math]::Floor(($TargetIterations * $GateFailureRatePercent) / (100.0 - $GateFailureRatePercent))
    return [Math]::Max(0, $maxFailures)
}

$resolvedPerfGateScript = Resolve-RepoPath -PathValue $PerfGateScriptPath
if (-not (Test-Path $resolvedPerfGateScript)) {
    throw "Perf gate script not found: $resolvedPerfGateScript"
}

$resolvedStartScript = Resolve-RepoPath -PathValue $StartGatewaysScriptPath
if ($AutoStartGateways -and -not (Test-Path $resolvedStartScript)) {
    throw "Start gateways script not found: $resolvedStartScript"
}

$resolvedRunlogsPath = Resolve-RepoPath -PathValue $RunlogsPath
$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath
New-Item -ItemType Directory -Path $resolvedRunlogsPath -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

$profileList = Resolve-ProfileList -ProfilesCsv $Profiles
$results = New-Object System.Collections.Generic.List[object]
$startedAt = [DateTimeOffset]::UtcNow

if ($AutoStartGateways) {
    $startArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $resolvedStartScript)
    if (-not [string]::IsNullOrWhiteSpace($HypothesisId)) {
        $startArgs += @("-HypothesisId", $HypothesisId)
    }

    & powershell @startArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start gateways before scale profiles run."
    }
}

$globalPass = $true
foreach ($parallelism in $profileList) {
    $gates = Get-GatesForParallelism -Parallelism $parallelism
    $effectiveAllowFailures = Resolve-AllowFailuresForProfile `
        -TargetIterations $IterationsPerProfile `
        -GateFailureRatePercent $gates.failure_rate_pct `
        -ExplicitAllowFailures $AllowFailuresPerProfile
    $profileSummaryPath = Join-Path $resolvedRunlogsPath ("probe_perf_gate.profile_p{0}.latest.json" -f $parallelism)

    $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedPerfGateScript `
        -HypothesisId $HypothesisId `
        -Iterations $IterationsPerProfile `
        -Parallelism $parallelism `
        -AllowFailures $effectiveAllowFailures `
        -P50GateMs $gates.p50 `
        -P95GateMs $gates.p95 `
        -MaxDurationGateMs $gates.max `
        -MaxFailureRatePercent $gates.failure_rate_pct `
        -SummaryPath $profileSummaryPath

    $exitCode = $LASTEXITCODE
    $jsonText = ($raw -join "`n")
    $summary = $jsonText | ConvertFrom-Json

    $profilePass = ($exitCode -eq 0) -and [bool]$summary.gate_passed
    if (-not $profilePass) {
        $globalPass = $false
    }

    $results.Add([PSCustomObject]@{
            parallelism = $parallelism
            gate_p50_ms = $gates.p50
            gate_p95_ms = $gates.p95
            gate_max_ms = $gates.max
            gate_failure_rate_pct = [double]$gates.failure_rate_pct
            effective_allow_failures = $effectiveAllowFailures
            gate_passed = $profilePass
            successful_iterations = [int]$summary.successful_iterations
            failed_attempts = [int]$summary.failed_attempts
            failure_rate_percent = [double]$summary.failure_rate_percent
            p50_ms = [double]$summary.p50_ms
            p95_ms = [double]$summary.p95_ms
            max_ms = [double]$summary.max_ms
            avg_ms = [double]$summary.avg_ms
            profile_summary_path = $profileSummaryPath
            gate_reasons = @($summary.gate_reasons)
        }) | Out-Null
}

$finishedAt = [DateTimeOffset]::UtcNow
$output = [PSCustomObject]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    hypothesis_id = $HypothesisId
    iterations_per_profile = $IterationsPerProfile
    allow_failures_per_profile = $AllowFailuresPerProfile
    allow_failures_mode = if ($AllowFailuresPerProfile -ge 0) { "explicit" } else { "auto_from_failure_rate_gate" }
    profiles = $profileList
    overall_pass = $globalPass
    duration_total_ms = [Math]::Max(0, [int]($finishedAt - $startedAt).TotalMilliseconds)
    results = $results
}

($output | ConvertTo-Json -Depth 10) | Set-Content -Path $resolvedSummaryPath -Encoding UTF8
$output | ConvertTo-Json -Depth 10

if (-not $globalPass) {
    exit 1
}
