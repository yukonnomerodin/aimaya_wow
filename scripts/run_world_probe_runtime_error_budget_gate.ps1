param(
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$PerfSummaryPath = "docs/handshake/runlogs/probe_perf_gate.latest.json",
    [string]$ScaleSummaryPath = "docs/handshake/runlogs/probe_scale_profiles.latest.json",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_runtime_error_budget_gate.latest.json",
    [string]$HypothesisId = "",
    [double]$MaxRelayFailureRatePercent = 8.0,
    [double]$MaxDbTimeoutRatePercent = 0.5,
    [double]$MaxDiagnosticsQueueSaturationRatePercent = 1.0,
    [int]$MinReportSampleSize = 12
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

function Try-LoadJsonFile {
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

function Get-NumberOrDefault {
    param(
        [object]$InputObject,
        [string]$PropertyName,
        [double]$DefaultValue = 0
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $prop = $InputObject.PSObject.Properties | Where-Object { $_.Name -eq $PropertyName } | Select-Object -First 1
    if ($null -eq $prop -or $null -eq $prop.Value) {
        return $DefaultValue
    }

    return [double]$prop.Value
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

function Get-RelayFailureRateFromPerfSummary {
    param([object]$PerfSummary)

    if ($null -eq $PerfSummary) {
        return $null
    }

    $rate = Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "failure_rate_percent" -DefaultValue -1
    if ($rate -ge 0) {
        return [double]$rate
    }

    $failed = Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "failed_attempts" -DefaultValue 0
    $attempts = Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "attempts_total" -DefaultValue 0
    if ($attempts -le 0) {
        return 0.0
    }

    return [double][Math]::Round(($failed * 100.0) / $attempts, 3)
}

function Get-WorstProfileFailureRateFromScaleSummary {
    param([object]$ScaleSummary)

    if ($null -eq $ScaleSummary) {
        return $null
    }

    $results = @($ScaleSummary.results)
    if ($results.Count -eq 0) {
        return $null
    }

    $worst = 0.0
    foreach ($profile in $results) {
        $rate = Get-NumberOrDefault -InputObject $profile -PropertyName "failure_rate_percent" -DefaultValue -1
        if ($rate -lt 0) {
            $failed = Get-NumberOrDefault -InputObject $profile -PropertyName "failed_attempts" -DefaultValue 0
            $succeeded = Get-NumberOrDefault -InputObject $profile -PropertyName "successful_iterations" -DefaultValue 0
            $attempts = $failed + $succeeded
            if ($attempts -gt 0) {
                $rate = [double][Math]::Round(($failed * 100.0) / $attempts, 3)
            }
            else {
                $rate = 0.0
            }
        }

        if ($rate -gt $worst) {
            $worst = $rate
        }
    }

    return [double]$worst
}

function Get-ReportSample {
    param(
        [string]$RunlogsDirectory,
        [string]$Hypothesis,
        [int]$TargetCount
    )

    $sample = New-Object System.Collections.Generic.List[object]
    $files = Get-ChildItem -Path $RunlogsDirectory -Filter "handshake_lab.*.json" |
        Sort-Object LastWriteTimeUtc -Descending
    foreach ($file in $files) {
        try {
            $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        }
        catch {
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($Hypothesis)) {
            $fileHypothesis = Get-StringOrDefault -InputObject $json -PropertyName "hypothesis_id" -DefaultValue ""
            if (-not [string]::Equals($fileHypothesis, $Hypothesis, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }

        $sample.Add([PSCustomObject]@{
                path = $file.FullName
                json = $json
            }) | Out-Null
        if ($sample.Count -ge $TargetCount) {
            break
        }
    }

    return [object[]]$sample.ToArray()
}

function Get-DbTimeoutRateFromReports {
    param([object[]]$ReportSample)

    if ($null -eq $ReportSample -or $ReportSample.Length -eq 0) {
        return [PSCustomObject]@{
            rate_percent = 0.0
            timeout_reports = 0
            sample_size = 0
        }
    }

    $timeoutReports = 0
    foreach ($entry in $ReportSample) {
        $invariants = @($entry.json.temporal_invariants)
        $hasTimeoutInvariant = $false
        foreach ($invariant in $invariants) {
            $name = Get-StringOrDefault -InputObject $invariant -PropertyName "Name" -DefaultValue ""
            $passed = [bool](Get-NumberOrDefault -InputObject $invariant -PropertyName "Passed" -DefaultValue 0)
            if ([string]::Equals($name, "db_auth_bridge_timeout_gate", [System.StringComparison]::Ordinal) -and -not $passed) {
                $hasTimeoutInvariant = $true
                break
            }
        }

        if ($hasTimeoutInvariant) {
            $timeoutReports++
        }
    }

    $rate = [double][Math]::Round(($timeoutReports * 100.0) / $ReportSample.Length, 3)
    return [PSCustomObject]@{
        rate_percent = $rate
        timeout_reports = $timeoutReports
        sample_size = $ReportSample.Length
    }
}

function Get-DiagnosticsQueueSaturationRateFromReports {
    param([object[]]$ReportSample)

    if ($null -eq $ReportSample -or $ReportSample.Length -eq 0) {
        return [PSCustomObject]@{
            rate_percent = 0.0
            saturation_events = 0
            enqueue_attempts = 0
        }
    }

    $oldest = $ReportSample[$ReportSample.Length - 1].json
    $newest = $ReportSample[0].json

    $oldAttempts = Get-NumberOrDefault -InputObject $oldest -PropertyName "handshake_diagnostics_queue_enqueue_attempt_total" -DefaultValue 0
    $newAttempts = Get-NumberOrDefault -InputObject $newest -PropertyName "handshake_diagnostics_queue_enqueue_attempt_total" -DefaultValue 0
    $oldSaturation = Get-NumberOrDefault -InputObject $oldest -PropertyName "handshake_diagnostics_queue_saturation_fallback_total" -DefaultValue 0
    $newSaturation = Get-NumberOrDefault -InputObject $newest -PropertyName "handshake_diagnostics_queue_saturation_fallback_total" -DefaultValue 0

    $deltaAttempts = [Math]::Max(0, $newAttempts - $oldAttempts)
    $deltaSaturation = [Math]::Max(0, $newSaturation - $oldSaturation)
    if ($deltaAttempts -le 0) {
        return [PSCustomObject]@{
            rate_percent = 0.0
            saturation_events = [int]$deltaSaturation
            enqueue_attempts = [int]$deltaAttempts
        }
    }

    $rate = [double][Math]::Round(($deltaSaturation * 100.0) / $deltaAttempts, 3)
    return [PSCustomObject]@{
        rate_percent = $rate
        saturation_events = [int]$deltaSaturation
        enqueue_attempts = [int]$deltaAttempts
    }
}

$resolvedRunlogsPath = Resolve-RepoPath -PathValue $RunlogsPath
$resolvedPerfSummaryPath = Resolve-RepoPath -PathValue $PerfSummaryPath
$resolvedScaleSummaryPath = Resolve-RepoPath -PathValue $ScaleSummaryPath
$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

$perfSummary = Try-LoadJsonFile -PathValue $resolvedPerfSummaryPath
$scaleSummary = Try-LoadJsonFile -PathValue $resolvedScaleSummaryPath

if ($null -ne $perfSummary -and -not [string]::IsNullOrWhiteSpace($HypothesisId)) {
    $perfHypothesis = Get-StringOrDefault -InputObject $perfSummary -PropertyName "hypothesis_id" -DefaultValue ""
    if (-not [string]::Equals($perfHypothesis, $HypothesisId, [System.StringComparison]::OrdinalIgnoreCase)) {
        $perfSummary = $null
    }
}

if ($null -ne $scaleSummary -and -not [string]::IsNullOrWhiteSpace($HypothesisId)) {
    $scaleHypothesis = Get-StringOrDefault -InputObject $scaleSummary -PropertyName "hypothesis_id" -DefaultValue ""
    if (-not [string]::Equals($scaleHypothesis, $HypothesisId, [System.StringComparison]::OrdinalIgnoreCase)) {
        $scaleSummary = $null
    }
}

$relayRateFromPerf = Get-RelayFailureRateFromPerfSummary -PerfSummary $perfSummary
$relayRateFromScale = Get-WorstProfileFailureRateFromScaleSummary -ScaleSummary $scaleSummary
$relayFailureRatePercent = 0.0
if ($null -ne $relayRateFromPerf -and $relayRateFromPerf -gt $relayFailureRatePercent) {
    $relayFailureRatePercent = $relayRateFromPerf
}

if ($null -ne $relayRateFromScale -and $relayRateFromScale -gt $relayFailureRatePercent) {
    $relayFailureRatePercent = $relayRateFromScale
}

$reportTargetCount = $MinReportSampleSize
if ($null -ne $perfSummary) {
    $reportTargetCount = [Math]::Max($reportTargetCount, [int](Get-NumberOrDefault -InputObject $perfSummary -PropertyName "successful_iterations" -DefaultValue 0))
}

if ($null -ne $scaleSummary) {
    $scaleSuccessful = 0
    foreach ($profile in @($scaleSummary.results)) {
        $scaleSuccessful += [int](Get-NumberOrDefault -InputObject $profile -PropertyName "successful_iterations" -DefaultValue 0)
    }

    $reportTargetCount = [Math]::Max($reportTargetCount, $scaleSuccessful)
}

$reportSample = Get-ReportSample -RunlogsDirectory $resolvedRunlogsPath -Hypothesis $HypothesisId -TargetCount $reportTargetCount
$dbRate = Get-DbTimeoutRateFromReports -ReportSample $reportSample
$diagRate = Get-DiagnosticsQueueSaturationRateFromReports -ReportSample $reportSample

$gatePassed = $true
$gateReasons = New-Object System.Collections.Generic.List[string]

if ($reportSample.Length -lt $MinReportSampleSize) {
    $gatePassed = $false
    $gateReasons.Add("insufficient_report_sample: min=$MinReportSampleSize actual=$($reportSample.Length)") | Out-Null
}

if ($relayFailureRatePercent -gt $MaxRelayFailureRatePercent) {
    $gatePassed = $false
    $gateReasons.Add("relay_failure_rate_gate_failed: gate_pct=$MaxRelayFailureRatePercent actual_pct=$relayFailureRatePercent") | Out-Null
}

if ($dbRate.rate_percent -gt $MaxDbTimeoutRatePercent) {
    $gatePassed = $false
    $gateReasons.Add("db_timeout_rate_gate_failed: gate_pct=$MaxDbTimeoutRatePercent actual_pct=$($dbRate.rate_percent)") | Out-Null
}

if ($diagRate.rate_percent -gt $MaxDiagnosticsQueueSaturationRatePercent) {
    $gatePassed = $false
    $gateReasons.Add("diagnostics_queue_saturation_rate_gate_failed: gate_pct=$MaxDiagnosticsQueueSaturationRatePercent actual_pct=$($diagRate.rate_percent)") | Out-Null
}

$summary = [ordered]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    hypothesis_id = $HypothesisId
    perf_summary_path = $resolvedPerfSummaryPath
    scale_summary_path = $resolvedScaleSummaryPath
    report_sample_size = $reportSample.Length
    report_sample_target = $reportTargetCount
    gates = [ordered]@{
        max_relay_failure_rate_percent = $MaxRelayFailureRatePercent
        max_db_timeout_rate_percent = $MaxDbTimeoutRatePercent
        max_diagnostics_queue_saturation_rate_percent = $MaxDiagnosticsQueueSaturationRatePercent
        min_report_sample_size = $MinReportSampleSize
    }
    observed = [ordered]@{
        relay_failure_rate_percent = [double][Math]::Round($relayFailureRatePercent, 3)
        relay_failure_rate_perf_percent = if ($null -eq $relayRateFromPerf) { $null } else { [double][Math]::Round($relayRateFromPerf, 3) }
        relay_failure_rate_scale_worst_profile_percent = if ($null -eq $relayRateFromScale) { $null } else { [double][Math]::Round($relayRateFromScale, 3) }
        db_timeout_rate_percent = [double]$dbRate.rate_percent
        db_timeout_reports = [int]$dbRate.timeout_reports
        diagnostics_queue_saturation_rate_percent = [double]$diagRate.rate_percent
        diagnostics_queue_saturation_events = [int]$diagRate.saturation_events
        diagnostics_queue_enqueue_attempts = [int]$diagRate.enqueue_attempts
    }
    gate_passed = $gatePassed
    gate_reasons = [string[]]$gateReasons.ToArray()
}

$summaryJson = $summary | ConvertTo-Json -Depth 10
$summaryJson | Set-Content -Path $resolvedSummaryPath -Encoding UTF8
$summaryJson

if (-not $gatePassed) {
    exit 1
}
