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
    [double]$PerfMaxSocketClosedFailureRatePercent = 5.0,
    [string]$PerfSocketClosedStageFailureCountBudgets = "",
    [string]$SocketClosedStageFailureRateBudgets = "post_ack_read:5,await_enter_encrypted:5,unknown_socket_stage:5",
    [double]$ScaleMaxRelayFailureRatePercent = 30.0,
    [string]$ScaleProfileRelayFailureRateBudgets = "1:8,4:10,8:15,16:24,32:28",
    [double]$ScaleMaxSocketClosedFailureRatePercent = 18.0,
    [string]$ScaleProfileSocketClosedFailureRateBudgets = "1:5,4:7,8:11,16:17,32:22",
    [string]$ScaleProfileSocketClosedStageFailureRateBudgets = "1:await_enter_encrypted:1,1:post_ack_read:1,1:unknown_socket_stage:1,4:await_enter_encrypted:1,4:post_ack_read:1,4:unknown_socket_stage:1,8:await_enter_encrypted:1,8:post_ack_read:1,8:unknown_socket_stage:1,16:await_enter_encrypted:1,16:post_ack_read:1,16:unknown_socket_stage:1,32:await_enter_encrypted:1,32:post_ack_read:1,32:unknown_socket_stage:1",
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

function Get-StringOrDefault {
    param(
        [object]$InputObject,
        [string]$PropertyName,
        [string]$DefaultValue = ""
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $prop = $InputObject.PSObject.Properties | Where-Object { $_.Name -eq $PropertyName } | Select-Object -First 1
    if ($null -eq $prop -or $null -eq $prop.Value) {
        return $DefaultValue
    }

    return [string]$prop.Value
}

function Invoke-ScriptStep {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [object[]]$ScriptArgs,
        [string]$SummaryPath = "",
        [string]$ExpectedHypothesisId = "",
        [string]$PassFlagProperty = ""
    )

    $stepStartedAt = [DateTimeOffset]::UtcNow
    $summaryExists = $false
    $summaryFresh = $true
    $summaryParseOk = $true
    $summaryHypothesisMatch = $true
    $summaryWrittenAtUtc = $null
    $summaryJson = $null
    $passFlagValue = $null

    if (-not [string]::IsNullOrWhiteSpace($SummaryPath) -and (Test-Path $SummaryPath)) {
        Remove-Item -Path $SummaryPath -Force -ErrorAction SilentlyContinue
    }

    $invokeArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $ScriptPath) + @($ScriptArgs)
    $stepOutput = @(& powershell @invokeArgs 2>&1)
    $exitCode = $LASTEXITCODE

    if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
        $summaryExists = Test-Path $SummaryPath
        if ($summaryExists) {
            $summaryItem = Get-Item -Path $SummaryPath
            $summaryWrittenAtUtc = [DateTimeOffset]$summaryItem.LastWriteTimeUtc
            $summaryFresh = ($summaryItem.LastWriteTimeUtc -ge $stepStartedAt.UtcDateTime.AddSeconds(-1))
            $summaryJson = Load-JsonOrNull -PathValue $SummaryPath
            $summaryParseOk = ($null -ne $summaryJson)

            if ($summaryParseOk -and -not [string]::IsNullOrWhiteSpace($ExpectedHypothesisId)) {
                $summaryHypothesis = Get-StringOrDefault -InputObject $summaryJson -PropertyName "hypothesis_id" -DefaultValue ""
                $summaryHypothesisMatch = [string]::Equals(
                    $summaryHypothesis,
                    $ExpectedHypothesisId,
                    [System.StringComparison]::OrdinalIgnoreCase)
            }

            if ($summaryParseOk -and -not [string]::IsNullOrWhiteSpace($PassFlagProperty)) {
                $passProp = $summaryJson.PSObject.Properties | Where-Object { $_.Name -eq $PassFlagProperty } | Select-Object -First 1
                if ($null -ne $passProp -and $null -ne $passProp.Value) {
                    $passFlagValue = [bool]$passProp.Value
                }
            }
        }
        else {
            $summaryFresh = $false
            $summaryParseOk = $false
            $summaryHypothesisMatch = $false
        }
    }

    $stepPassed = ($exitCode -eq 0)
    if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
        $stepPassed = $stepPassed -and $summaryExists -and $summaryFresh -and $summaryParseOk -and $summaryHypothesisMatch
        if ($null -ne $passFlagValue) {
            $stepPassed = $stepPassed -and [bool]$passFlagValue
        }
    }

    $outputLines = @($stepOutput | ForEach-Object { [string]$_ })
    $tailCount = [Math]::Min(10, $outputLines.Count)
    $outputTail = @()
    if ($tailCount -gt 0) {
        $tailStart = [Math]::Max(0, $outputLines.Count - $tailCount)
        $outputTail = @($outputLines | Select-Object -Skip $tailStart)
    }

    return [PSCustomObject]@{
        name = $Name
        exit_code = [int]$exitCode
        passed = [bool]$stepPassed
        summary_path = $SummaryPath
        summary_exists = [bool]$summaryExists
        summary_fresh = [bool]$summaryFresh
        summary_parse_ok = [bool]$summaryParseOk
        summary_hypothesis_match = [bool]$summaryHypothesisMatch
        summary_pass_flag = $passFlagValue
        summary_written_at_utc = if ($null -eq $summaryWrittenAtUtc) { $null } else { $summaryWrittenAtUtc.ToString("o") }
        output_tail = [string[]]$outputTail
        summary_json = $summaryJson
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

$stepResults = [ordered]@{}

$startStep = Invoke-ScriptStep `
    -Name "start_gateways" `
    -ScriptPath $resolvedStartGatewaysScriptPath `
    -ScriptArgs @("-HypothesisId", $HypothesisId)
$stepResults[$startStep.name] = $startStep
if (-not $startStep.passed) {
    throw ("Failed to start gateways for soak baseline. ExitCode={0}. OutputTail={1}" -f `
            $startStep.exit_code, ($startStep.output_tail -join " | "))
}

$capacityStep = Invoke-ScriptStep `
    -Name "capacity_benchmark" `
    -ScriptPath $resolvedCapacityBenchmarkScriptPath `
    -ScriptArgs @(
        "-HypothesisId", $HypothesisId,
        "-Rounds", $Rounds,
        "-IterationsPerProfile", $IterationsPerProfile,
        "-AllowFailuresPerProfile", -1,
        "-Profiles", $Profiles,
        "-SummaryPath", $capacitySummaryPath,
        "-MaxFailureRatePctP1", $MaxFailureRatePctP1,
        "-MaxFailureRatePctP4", $MaxFailureRatePctP4,
        "-MaxFailureRatePctP8", $MaxFailureRatePctP8,
        "-MaxFailureRatePctP16", $MaxFailureRatePctP16,
        "-MaxFailureRatePctP32", $MaxFailureRatePctP32) `
    -SummaryPath $capacitySummaryPath `
    -ExpectedHypothesisId $HypothesisId
$stepResults[$capacityStep.name] = $capacityStep

$scaleStep = Invoke-ScriptStep `
    -Name "scale_profiles" `
    -ScriptPath $resolvedScaleProfilesScriptPath `
    -ScriptArgs @(
        "-HypothesisId", $HypothesisId,
        "-IterationsPerProfile", $IterationsPerProfile,
        "-AllowFailuresPerProfile", -1,
        "-Profiles", $Profiles,
        "-SummaryPath", $scaleSummaryPath,
        "-MaxFailureRatePctP1", $MaxFailureRatePctP1,
        "-MaxFailureRatePctP4", $MaxFailureRatePctP4,
        "-MaxFailureRatePctP8", $MaxFailureRatePctP8,
        "-MaxFailureRatePctP16", $MaxFailureRatePctP16,
        "-MaxFailureRatePctP32", $MaxFailureRatePctP32) `
    -SummaryPath $scaleSummaryPath `
    -ExpectedHypothesisId $HypothesisId `
    -PassFlagProperty "overall_pass"
$stepResults[$scaleStep.name] = $scaleStep

$perfStep = Invoke-ScriptStep `
    -Name "perf_gate" `
    -ScriptPath $resolvedPerfGateScriptPath `
    -ScriptArgs @(
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
        "-SummaryPath", $perfSummaryPath) `
    -SummaryPath $perfSummaryPath `
    -ExpectedHypothesisId $HypothesisId `
    -PassFlagProperty "gate_passed"
$stepResults[$perfStep.name] = $perfStep

$runtimePerfStep = Invoke-ScriptStep `
    -Name "runtime_gate_perf_context" `
    -ScriptPath $resolvedRuntimeBudgetGateScriptPath `
    -ScriptArgs @(
        "-HypothesisId", $HypothesisId,
        "-PerfSummaryPath", $perfSummaryPath,
        "-SummaryPath", $runtimePerfSummaryPath,
        "-MaxRelayFailureRatePercent", $PerfMaxFailureRatePercent,
        "-MaxSocketClosedFailureRatePercent", $PerfMaxSocketClosedFailureRatePercent,
        "-SocketClosedStageFailureRateBudgets", $SocketClosedStageFailureRateBudgets,
        "-MaxDbTimeoutRatePercent", $MaxDbTimeoutRatePercent,
        "-MaxDiagnosticsQueueSaturationRatePercent", $MaxDiagnosticsQueueSaturationRatePercent) `
    -SummaryPath $runtimePerfSummaryPath `
    -ExpectedHypothesisId $HypothesisId `
    -PassFlagProperty "gate_passed"
$stepResults[$runtimePerfStep.name] = $runtimePerfStep

$runtimeScaleStep = Invoke-ScriptStep `
    -Name "runtime_gate_scale_context" `
    -ScriptPath $resolvedRuntimeBudgetGateScriptPath `
    -ScriptArgs @(
        "-HypothesisId", $HypothesisId,
        "-PerfSummaryPath", $perfSummaryPath,
        "-ScaleSummaryPath", $scaleSummaryPath,
        "-SummaryPath", $runtimeScaleSummaryPath,
        "-MaxRelayFailureRatePercent", $ScaleMaxRelayFailureRatePercent,
        "-ScaleProfileRelayFailureRateBudgets", $ScaleProfileRelayFailureRateBudgets,
        "-MaxSocketClosedFailureRatePercent", $ScaleMaxSocketClosedFailureRatePercent,
        "-ScaleProfileSocketClosedFailureRateBudgets", $ScaleProfileSocketClosedFailureRateBudgets,
        "-ScaleProfileSocketClosedStageFailureRateBudgets", $ScaleProfileSocketClosedStageFailureRateBudgets,
        "-SocketClosedStageFailureRateBudgets", $SocketClosedStageFailureRateBudgets,
        "-MaxDbTimeoutRatePercent", $MaxDbTimeoutRatePercent,
        "-MaxDiagnosticsQueueSaturationRatePercent", $MaxDiagnosticsQueueSaturationRatePercent) `
    -SummaryPath $runtimeScaleSummaryPath `
    -ExpectedHypothesisId $HypothesisId `
    -PassFlagProperty "gate_passed"
$stepResults[$runtimeScaleStep.name] = $runtimeScaleStep

$startExitCode = [int]$startStep.exit_code
$capacityExitCode = [int]$capacityStep.exit_code
$scaleExitCode = [int]$scaleStep.exit_code
$perfExitCode = [int]$perfStep.exit_code
$runtimePerfExitCode = [int]$runtimePerfStep.exit_code
$runtimeScaleExitCode = [int]$runtimeScaleStep.exit_code

$capacitySummary = if ($null -ne $capacityStep.summary_json) { $capacityStep.summary_json } else { Load-JsonOrNull -PathValue $capacitySummaryPath }
$scaleSummary = if ($null -ne $scaleStep.summary_json) { $scaleStep.summary_json } else { Load-JsonOrNull -PathValue $scaleSummaryPath }
$perfSummary = if ($null -ne $perfStep.summary_json) { $perfStep.summary_json } else { Load-JsonOrNull -PathValue $perfSummaryPath }
$runtimePerfSummary = if ($null -ne $runtimePerfStep.summary_json) { $runtimePerfStep.summary_json } else { Load-JsonOrNull -PathValue $runtimePerfSummaryPath }
$runtimeScaleSummary = if ($null -ne $runtimeScaleStep.summary_json) { $runtimeScaleStep.summary_json } else { Load-JsonOrNull -PathValue $runtimeScaleSummaryPath }

$allStepsPassed = @(
    [bool]$startStep.passed,
    [bool]$capacityStep.passed,
    [bool]$scaleStep.passed,
    [bool]$perfStep.passed,
    [bool]$runtimePerfStep.passed,
    [bool]$runtimeScaleStep.passed
) -notcontains $false

$profilesNormalized = @()
try {
    $profilesNormalized = @($Profiles.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object { [int]$_.Trim() } |
        Select-Object -Unique)
}
catch {
    $profilesNormalized = @()
}

$finishedAt = [DateTimeOffset]::UtcNow
$summary = [ordered]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    hypothesis_id = $HypothesisId
    rounds = $Rounds
    iterations_per_profile = $IterationsPerProfile
    profiles_csv = $Profiles
    profiles = @($profilesNormalized)
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
    step_validations = [ordered]@{
        start_gateways = [ordered]@{
            passed = [bool]$startStep.passed
            output_tail = @($startStep.output_tail)
        }
        capacity_benchmark = [ordered]@{
            passed = [bool]$capacityStep.passed
            summary_exists = [bool]$capacityStep.summary_exists
            summary_fresh = [bool]$capacityStep.summary_fresh
            summary_parse_ok = [bool]$capacityStep.summary_parse_ok
            summary_hypothesis_match = [bool]$capacityStep.summary_hypothesis_match
            output_tail = @($capacityStep.output_tail)
        }
        scale_profiles = [ordered]@{
            passed = [bool]$scaleStep.passed
            summary_exists = [bool]$scaleStep.summary_exists
            summary_fresh = [bool]$scaleStep.summary_fresh
            summary_parse_ok = [bool]$scaleStep.summary_parse_ok
            summary_hypothesis_match = [bool]$scaleStep.summary_hypothesis_match
            summary_pass_flag = $scaleStep.summary_pass_flag
            output_tail = @($scaleStep.output_tail)
        }
        perf_gate = [ordered]@{
            passed = [bool]$perfStep.passed
            summary_exists = [bool]$perfStep.summary_exists
            summary_fresh = [bool]$perfStep.summary_fresh
            summary_parse_ok = [bool]$perfStep.summary_parse_ok
            summary_hypothesis_match = [bool]$perfStep.summary_hypothesis_match
            summary_pass_flag = $perfStep.summary_pass_flag
            output_tail = @($perfStep.output_tail)
        }
        runtime_gate_perf_context = [ordered]@{
            passed = [bool]$runtimePerfStep.passed
            summary_exists = [bool]$runtimePerfStep.summary_exists
            summary_fresh = [bool]$runtimePerfStep.summary_fresh
            summary_parse_ok = [bool]$runtimePerfStep.summary_parse_ok
            summary_hypothesis_match = [bool]$runtimePerfStep.summary_hypothesis_match
            summary_pass_flag = $runtimePerfStep.summary_pass_flag
            output_tail = @($runtimePerfStep.output_tail)
        }
        runtime_gate_scale_context = [ordered]@{
            passed = [bool]$runtimeScaleStep.passed
            summary_exists = [bool]$runtimeScaleStep.summary_exists
            summary_fresh = [bool]$runtimeScaleStep.summary_fresh
            summary_parse_ok = [bool]$runtimeScaleStep.summary_parse_ok
            summary_hypothesis_match = [bool]$runtimeScaleStep.summary_hypothesis_match
            summary_pass_flag = $runtimeScaleStep.summary_pass_flag
            output_tail = @($runtimeScaleStep.output_tail)
        }
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
