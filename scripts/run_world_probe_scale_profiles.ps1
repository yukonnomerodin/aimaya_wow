param(
    [string]$PerfGateScriptPath = "scripts/run_world_probe_perf_gate.ps1",
    [string]$StartGatewaysScriptPath = "scripts/start_retail_gateways.ps1",
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_scale_profiles.latest.json",
    [string]$HypothesisId = "",
    [int]$IterationsPerProfile = 16,
    [int]$AllowFailuresPerProfile = 4,
    [switch]$AutoStartGateways,
    [string]$Profiles = "1,4,8,16",
    [int]$P50GateP1 = 420,
    [int]$P95GateP1 = 520,
    [int]$MaxGateP1 = 620,
    [int]$P50GateP4 = 500,
    [int]$P95GateP4 = 600,
    [int]$MaxGateP4 = 620,
    [int]$P50GateP8 = 700,
    [int]$P95GateP8 = 900,
    [int]$MaxGateP8 = 1200,
    [int]$P50GateP16 = 1100,
    [int]$P95GateP16 = 1400,
    [int]$MaxGateP16 = 2200
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
            return [PSCustomObject]@{ p50 = $P50GateP1; p95 = $P95GateP1; max = $MaxGateP1 }
        }
        4 {
            return [PSCustomObject]@{ p50 = $P50GateP4; p95 = $P95GateP4; max = $MaxGateP4 }
        }
        8 {
            return [PSCustomObject]@{ p50 = $P50GateP8; p95 = $P95GateP8; max = $MaxGateP8 }
        }
        16 {
            return [PSCustomObject]@{ p50 = $P50GateP16; p95 = $P95GateP16; max = $MaxGateP16 }
        }
        default {
            throw "No gate configured for parallelism=$Parallelism. Supported defaults: 1,4,8,16."
        }
    }
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
    $profileSummaryPath = Join-Path $resolvedRunlogsPath ("probe_perf_gate.profile_p{0}.latest.json" -f $parallelism)

    $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedPerfGateScript `
        -HypothesisId $HypothesisId `
        -Iterations $IterationsPerProfile `
        -Parallelism $parallelism `
        -AllowFailures $AllowFailuresPerProfile `
        -P50GateMs $gates.p50 `
        -P95GateMs $gates.p95 `
        -MaxDurationGateMs $gates.max `
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
            gate_passed = $profilePass
            successful_iterations = [int]$summary.successful_iterations
            failed_attempts = [int]$summary.failed_attempts
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
