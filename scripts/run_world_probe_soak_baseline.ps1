param(
    [string]$HypothesisId = "",
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_soak_baseline.latest.json",
    [string]$StartGatewaysScriptPath = "scripts/start_retail_gateways.ps1",
    [string]$CapacityBenchmarkScriptPath = "scripts/run_world_probe_capacity_benchmark.ps1",
    [string]$ScaleProfilesScriptPath = "scripts/run_world_probe_scale_profiles.ps1",
    [string]$PerfGateScriptPath = "scripts/run_world_probe_perf_gate.ps1",
    [string]$RuntimeBudgetGateScriptPath = "scripts/run_world_probe_runtime_error_budget_gate.ps1",
    [int]$Rounds = 8,
    [int]$IterationsPerProfile = 24,
    [string]$Profiles = "1,4,8,16,32",
    [int]$PerfIterations = 60,
    [int]$PerfParallelism = 4,
    [int]$PerfP50GateMs = 500,
    [int]$PerfP95GateMs = 560,
    [int]$PerfMaxGateMs = 650,
    [double]$PerfMaxFailureRatePercent = 8.0,
    [int]$PerfMaxSocketClosedFailures = -1,
    [double]$PerfMaxSocketClosedFailureRatePercent = 6.0,
    [string]$PerfSocketClosedStageFailureCountBudgets = "",
    [string]$SocketClosedStageFailureRateBudgets = "",
    [double]$ScaleMaxRelayFailureRatePercent = 30.0,
    [string]$ScaleProfileRelayFailureRateBudgets = "1:8,4:10,8:15,16:24,32:28",
    [double]$ScaleMaxSocketClosedFailureRatePercent = 20.0,
    [string]$ScaleProfileSocketClosedFailureRateBudgets = "1:6,4:8,8:12,16:18,32:24",
    [double]$MaxDbTimeoutRatePercent = 0.5,
    [double]$MaxDiagnosticsQueueSaturationRatePercent = 1.0,
    [double]$MaxFailureRatePctP1 = 8.0,
    [double]$MaxFailureRatePctP4 = 10.0,
    [double]$MaxFailureRatePctP8 = 15.0,
    [double]$MaxFailureRatePctP16 = 24.0,
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

function Load-JsonOrNull {
    param([string]$PathValue)

    if (-not (Test-Path $PathValue)) {
        return $null
    }

    try {
        return Get-Content -Path $PathValue -Raw | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

if ($Rounds -le 0) { throw "Rounds must be > 0." }
if ($IterationsPerProfile -le 0) { throw "IterationsPerProfile must be > 0." }
if ($PerfIterations -le 0) { throw "PerfIterations must be > 0." }
if ($PerfParallelism -le 0) { throw "PerfParallelism must be > 0." }

$resolvedRunlogsPath = Resolve-RepoPath -PathValue $RunlogsPath
$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath
$resolvedStartGatewaysScriptPath = Resolve-RepoPath -PathValue $StartGatewaysScriptPath
$resolvedCapacityBenchmarkScriptPath = Resolve-RepoPath -PathValue $CapacityBenchmarkScriptPath
$resolvedScaleProfilesScriptPath = Resolve-RepoPath -PathValue $ScaleProfilesScriptPath
$resolvedPerfGateScriptPath = Resolve-RepoPath -PathValue $PerfGateScriptPath
$resolvedRuntimeBudgetGateScriptPath = Resolve-RepoPath -PathValue $RuntimeBudgetGateScriptPath

foreach ($requiredPath in @(
        $resolvedStartGatewaysScriptPath,
        $resolvedCapacityBenchmarkScriptPath,
        $resolvedScaleProfilesScriptPath,
        $resolvedPerfGateScriptPath,
        $resolvedRuntimeBudgetGateScriptPath))
{
    if (-not (Test-Path $requiredPath)) {
        throw "Required script not found: $requiredPath"
    }
}

New-Item -ItemType Directory -Path $resolvedRunlogsPath -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

$startedAt = [DateTimeOffset]::UtcNow

$capacitySummaryPath = Join-Path $resolvedRunlogsPath "probe_capacity_benchmark.soak.latest.json"
$scaleSummaryPath = Join-Path $resolvedRunlogsPath "probe_scale_profiles.soak.latest.json"
$perfSummaryPath = Join-Path $resolvedRunlogsPath "probe_perf_gate.soak.latest.json"
$runtimePerfSummaryPath = Join-Path $resolvedRunlogsPath "probe_runtime_error_budget_gate.soak_perf.latest.json"
$runtimeScaleSummaryPath = Join-Path $resolvedRunlogsPath "probe_runtime_error_budget_gate.soak_scale.latest.json"

& powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedStartGatewaysScriptPath -HypothesisId $HypothesisId
$startExitCode = $LASTEXITCODE
if ($startExitCode -ne 0) {
    throw "Failed to start gateways for soak baseline."
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedCapacityBenchmarkScriptPath `
    -HypothesisId $HypothesisId `
    -Rounds $Rounds `
    -IterationsPerProfile $IterationsPerProfile `
    -AllowFailuresPerProfile -1 `
    -Profiles $Profiles `
    -SummaryPath $capacitySummaryPath `
    -MaxFailureRatePctP1 $MaxFailureRatePctP1 `
    -MaxFailureRatePctP4 $MaxFailureRatePctP4 `
    -MaxFailureRatePctP8 $MaxFailureRatePctP8 `
    -MaxFailureRatePctP16 $MaxFailureRatePctP16 `
    -MaxFailureRatePctP32 $MaxFailureRatePctP32
$capacityExitCode = $LASTEXITCODE

& powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedScaleProfilesScriptPath `
    -HypothesisId $HypothesisId `
    -IterationsPerProfile $IterationsPerProfile `
    -AllowFailuresPerProfile -1 `
    -Profiles $Profiles `
    -SummaryPath $scaleSummaryPath `
    -MaxFailureRatePctP1 $MaxFailureRatePctP1 `
    -MaxFailureRatePctP4 $MaxFailureRatePctP4 `
    -MaxFailureRatePctP8 $MaxFailureRatePctP8 `
    -MaxFailureRatePctP16 $MaxFailureRatePctP16 `
    -MaxFailureRatePctP32 $MaxFailureRatePctP32
$scaleExitCode = $LASTEXITCODE

$perfArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $resolvedPerfGateScriptPath,
    "-HypothesisId", $HypothesisId,
    "-Iterations", $PerfIterations,
    "-Parallelism", $PerfParallelism,
    "-P50GateMs", $PerfP50GateMs,
    "-P95GateMs", $PerfP95GateMs,
    "-MaxDurationGateMs", $PerfMaxGateMs,
    "-MaxFailureRatePercent", $PerfMaxFailureRatePercent,
    "-MaxSocketClosedFailures", $PerfMaxSocketClosedFailures,
    "-MaxSocketClosedFailureRatePercent", $PerfMaxSocketClosedFailureRatePercent,
    "-SocketClosedFailureStageBudgets", $PerfSocketClosedStageFailureCountBudgets,
    "-SummaryPath", $perfSummaryPath
)
& powershell @perfArgs
$perfExitCode = $LASTEXITCODE

$runtimePerfArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $resolvedRuntimeBudgetGateScriptPath,
    "-HypothesisId", $HypothesisId,
    "-PerfSummaryPath", $perfSummaryPath,
    "-SummaryPath", $runtimePerfSummaryPath,
    "-MaxRelayFailureRatePercent", $PerfMaxFailureRatePercent,
    "-MaxSocketClosedFailureRatePercent", $PerfMaxSocketClosedFailureRatePercent,
    "-SocketClosedStageFailureRateBudgets", $SocketClosedStageFailureRateBudgets,
    "-MaxDbTimeoutRatePercent", $MaxDbTimeoutRatePercent,
    "-MaxDiagnosticsQueueSaturationRatePercent", $MaxDiagnosticsQueueSaturationRatePercent
)
& powershell @runtimePerfArgs
$runtimePerfExitCode = $LASTEXITCODE

$runtimeScaleArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $resolvedRuntimeBudgetGateScriptPath,
    "-HypothesisId", $HypothesisId,
    "-PerfSummaryPath", $perfSummaryPath,
    "-ScaleSummaryPath", $scaleSummaryPath,
    "-SummaryPath", $runtimeScaleSummaryPath,
    "-MaxRelayFailureRatePercent", $ScaleMaxRelayFailureRatePercent,
    "-ScaleProfileRelayFailureRateBudgets", $ScaleProfileRelayFailureRateBudgets,
    "-MaxSocketClosedFailureRatePercent", $ScaleMaxSocketClosedFailureRatePercent,
    "-ScaleProfileSocketClosedFailureRateBudgets", $ScaleProfileSocketClosedFailureRateBudgets,
    "-SocketClosedStageFailureRateBudgets", $SocketClosedStageFailureRateBudgets,
    "-MaxDbTimeoutRatePercent", $MaxDbTimeoutRatePercent,
    "-MaxDiagnosticsQueueSaturationRatePercent", $MaxDiagnosticsQueueSaturationRatePercent
)
& powershell @runtimeScaleArgs
$runtimeScaleExitCode = $LASTEXITCODE

$capacitySummary = Load-JsonOrNull -PathValue $capacitySummaryPath
$scaleSummary = Load-JsonOrNull -PathValue $scaleSummaryPath
$perfSummary = Load-JsonOrNull -PathValue $perfSummaryPath
$runtimePerfSummary = Load-JsonOrNull -PathValue $runtimePerfSummaryPath
$runtimeScaleSummary = Load-JsonOrNull -PathValue $runtimeScaleSummaryPath

$allStepsPassed = @(
    ($startExitCode -eq 0),
    ($capacityExitCode -eq 0),
    ($scaleExitCode -eq 0),
    ($perfExitCode -eq 0),
    ($runtimePerfExitCode -eq 0),
    ($runtimeScaleExitCode -eq 0)
) -notcontains $false

$finishedAt = [DateTimeOffset]::UtcNow
$summary = [ordered]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    hypothesis_id = $HypothesisId
    rounds = $Rounds
    iterations_per_profile = $IterationsPerProfile
    profiles = $Profiles
    perf_iterations = $PerfIterations
    perf_parallelism = $PerfParallelism
    perf_gates = [ordered]@{
        p50_ms = $PerfP50GateMs
        p95_ms = $PerfP95GateMs
        max_ms = $PerfMaxGateMs
        max_failure_rate_percent = $PerfMaxFailureRatePercent
        max_socket_closed_failures = $PerfMaxSocketClosedFailures
        max_socket_closed_failure_rate_percent = $PerfMaxSocketClosedFailureRatePercent
        socket_closed_stage_failure_count_budgets = $PerfSocketClosedStageFailureCountBudgets
        socket_closed_stage_failure_rate_budgets = $SocketClosedStageFailureRateBudgets
    }
    scale_gates = [ordered]@{
        max_relay_failure_rate_percent = $ScaleMaxRelayFailureRatePercent
        scale_profile_relay_failure_rate_budgets = $ScaleProfileRelayFailureRateBudgets
        max_socket_closed_failure_rate_percent = $ScaleMaxSocketClosedFailureRatePercent
        scale_profile_socket_closed_failure_rate_budgets = $ScaleProfileSocketClosedFailureRateBudgets
        socket_closed_stage_failure_rate_budgets = $SocketClosedStageFailureRateBudgets
        max_db_timeout_rate_percent = $MaxDbTimeoutRatePercent
        max_diagnostics_queue_saturation_rate_percent = $MaxDiagnosticsQueueSaturationRatePercent
    }
    step_exit_codes = [ordered]@{
        start_gateways = $startExitCode
        capacity_benchmark = $capacityExitCode
        scale_profiles = $scaleExitCode
        perf_gate = $perfExitCode
        runtime_gate_perf_context = $runtimePerfExitCode
        runtime_gate_scale_context = $runtimeScaleExitCode
    }
    overall_pass = $allStepsPassed
    artifacts = [ordered]@{
        capacity_benchmark_summary = $capacitySummaryPath
        scale_profiles_summary = $scaleSummaryPath
        perf_gate_summary = $perfSummaryPath
        runtime_gate_perf_summary = $runtimePerfSummaryPath
        runtime_gate_scale_summary = $runtimeScaleSummaryPath
    }
    observed = [ordered]@{
        capacity_recommendations = if ($null -eq $capacitySummary) { @() } else { @($capacitySummary.recommendations) }
        scale_overall_pass = if ($null -eq $scaleSummary) { $false } else { [bool]$scaleSummary.overall_pass }
        perf_gate_passed = if ($null -eq $perfSummary) { $false } else { [bool]$perfSummary.gate_passed }
        runtime_perf_gate_passed = if ($null -eq $runtimePerfSummary) { $false } else { [bool]$runtimePerfSummary.gate_passed }
        runtime_scale_gate_passed = if ($null -eq $runtimeScaleSummary) { $false } else { [bool]$runtimeScaleSummary.gate_passed }
    }
    duration_total_ms = [Math]::Max(0, [int]($finishedAt - $startedAt).TotalMilliseconds)
}

$summaryJson = $summary | ConvertTo-Json -Depth 12
$summaryJson | Set-Content -Path $resolvedSummaryPath -Encoding UTF8
$summaryJson

if (-not $allStepsPassed) {
    exit 1
}
