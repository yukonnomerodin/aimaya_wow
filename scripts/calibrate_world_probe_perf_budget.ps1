param(
    [string]$ProbeGateScriptPath = "scripts/run_world_probe_perf_gate.ps1",
    [string]$StartGatewaysScriptPath = "scripts/start_retail_gateways.ps1",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_perf_budget_calibration.latest.json",
    [string]$HypothesisId = "",
    [int]$Runs = 5,
    [int]$IterationsPerRun = 20,
    [int]$Parallelism = 4,
    [int]$AllowFailures = 4,
    [double]$P50SafetyMultiplier = 1.20,
    [double]$P95SafetyMultiplier = 1.20,
    [double]$MaxSafetyMultiplier = 1.15,
    [switch]$AutoStartGateways
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

if ($Runs -le 0) { throw "Runs must be > 0." }
if ($IterationsPerRun -le 0) { throw "IterationsPerRun must be > 0." }
if ($Parallelism -le 0) { throw "Parallelism must be > 0." }

$resolvedGateScript = Resolve-RepoPath -PathValue $ProbeGateScriptPath
if (-not (Test-Path $resolvedGateScript)) {
    throw "Perf gate script not found: $resolvedGateScript"
}

$resolvedStartScript = Resolve-RepoPath -PathValue $StartGatewaysScriptPath
if ($AutoStartGateways -and -not (Test-Path $resolvedStartScript)) {
    throw "Start gateways script not found: $resolvedStartScript"
}

$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

if ($AutoStartGateways) {
    $startArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $resolvedStartScript)
    if (-not [string]::IsNullOrWhiteSpace($HypothesisId)) {
        $startArgs += @("-HypothesisId", $HypothesisId)
    }

    & powershell @startArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start retail gateways for calibration."
    }
}

$rows = New-Object System.Collections.Generic.List[object]
$startedAt = [DateTimeOffset]::UtcNow

for ($i = 1; $i -le $Runs; $i++) {
    $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedGateScript `
        -HypothesisId $HypothesisId `
        -Iterations $IterationsPerRun `
        -Parallelism $Parallelism `
        -AllowFailures $AllowFailures `
        -P50GateMs 0 `
        -P95GateMs 0 `
        -MaxDurationGateMs 0

    if ($LASTEXITCODE -ne 0) {
        throw "Perf gate baseline run $i failed."
    }

    $jsonText = ($raw -join "`n")
    $summary = $jsonText | ConvertFrom-Json
    $rows.Add([PSCustomObject]@{
            run = $i
            p50_ms = [double]$summary.p50_ms
            p95_ms = [double]$summary.p95_ms
            max_ms = [double]$summary.max_ms
            avg_ms = [double]$summary.avg_ms
            failed_attempts = [int]$summary.failed_attempts
            successful_iterations = [int]$summary.successful_iterations
        }) | Out-Null
}

$maxP50 = ($rows | Measure-Object -Property p50_ms -Maximum).Maximum
$maxP95 = ($rows | Measure-Object -Property p95_ms -Maximum).Maximum
$maxMax = ($rows | Measure-Object -Property max_ms -Maximum).Maximum
$recommendedP50 = [int][Math]::Ceiling($maxP50 * $P50SafetyMultiplier)
$recommendedP95 = [int][Math]::Ceiling($maxP95 * $P95SafetyMultiplier)
$recommendedMax = [int][Math]::Ceiling($maxMax * $MaxSafetyMultiplier)
$finishedAt = [DateTimeOffset]::UtcNow

$result = [PSCustomObject]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    hypothesis_id = $HypothesisId
    runs = $Runs
    iterations_per_run = $IterationsPerRun
    parallelism = $Parallelism
    allow_failures = $AllowFailures
    p50_safety_multiplier = $P50SafetyMultiplier
    p95_safety_multiplier = $P95SafetyMultiplier
    max_safety_multiplier = $MaxSafetyMultiplier
    max_observed_p50_ms = [double]$maxP50
    max_observed_p95_ms = [double]$maxP95
    max_observed_max_ms = [double]$maxMax
    recommended_p50_gate_ms = $recommendedP50
    recommended_p95_gate_ms = $recommendedP95
    recommended_max_gate_ms = $recommendedMax
    duration_total_ms = [Math]::Max(0, [int]($finishedAt - $startedAt).TotalMilliseconds)
    samples = $rows
}

($result | ConvertTo-Json -Depth 8) | Set-Content -Path $resolvedSummaryPath -Encoding UTF8
$result | ConvertTo-Json -Depth 8
