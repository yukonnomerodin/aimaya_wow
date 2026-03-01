param(
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$PerfSummaryPath = "docs/handshake/runlogs/probe_perf_gate.latest.json",
    [string]$ScaleSummaryPath = "",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_runtime_error_budget_gate.latest.json",
    [string]$HypothesisId = "",
    [double]$MaxRelayFailureRatePercent = 8.0,
    [string]$ScaleProfileRelayFailureRateBudgets = "1:8,4:10,8:15,16:24,32:28",
    [double]$MaxSocketClosedFailureRatePercent = -1,
    [string]$ScaleProfileSocketClosedFailureRateBudgets = "",
    [string]$SocketClosedStageFailureRateBudgets = "",
    [string]$ScaleProfileSocketClosedStageFailureRateBudgets = "",
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

function Get-SocketClosedFailureRateFromPerfSummary {
    param([object]$PerfSummary)

    if ($null -eq $PerfSummary) {
        return $null
    }

    $rate = Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "socket_closed_failure_rate_percent" -DefaultValue -1
    if ($rate -ge 0) {
        return [double]$rate
    }

    $socketClosedFailures = Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "socket_closed_failures" -DefaultValue -1
    $attempts = Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "attempts_total" -DefaultValue 0
    if ($socketClosedFailures -ge 0 -and $attempts -gt 0) {
        return [double][Math]::Round(($socketClosedFailures * 100.0) / $attempts, 3)
    }

    $failureBucketsProp = $PerfSummary.PSObject.Properties | Where-Object { $_.Name -eq "failure_buckets" } | Select-Object -First 1
    if ($null -eq $failureBucketsProp -or $null -eq $failureBucketsProp.Value) {
        return 0.0
    }

    $socketClosedBucketValue = $failureBucketsProp.Value.PSObject.Properties | Where-Object { $_.Name -eq "socket_closed_during_read" } | Select-Object -First 1
    if ($null -eq $socketClosedBucketValue -or $null -eq $socketClosedBucketValue.Value) {
        return 0.0
    }

    $socketClosedFailures = [double]$socketClosedBucketValue.Value
    if ($attempts -le 0) {
        return 0.0
    }

    return [double][Math]::Round(($socketClosedFailures * 100.0) / $attempts, 3)
}

function Parse-ScaleProfileRelayFailureRateBudgets {
    param([string]$BudgetCsv)

    $budgetMap = @{}
    if ([string]::IsNullOrWhiteSpace($BudgetCsv)) {
        return $budgetMap
    }

    $tokens = $BudgetCsv.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
    foreach ($token in $tokens) {
        $entry = $token.Trim()
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        $parts = $entry.Split(':', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Length -ne 2) {
            throw "Invalid ScaleProfileRelayFailureRateBudgets entry '$entry'. Expected format: parallelism:percent."
        }

        $parallelism = [int]$parts[0].Trim()
        $budgetPercent = [double]$parts[1].Trim()
        if ($parallelism -le 0) {
            throw "Invalid profile parallelism in ScaleProfileRelayFailureRateBudgets entry '$entry'."
        }

        if ($budgetPercent -lt 0) {
            throw "Invalid failure-rate budget in ScaleProfileRelayFailureRateBudgets entry '$entry'. Must be >= 0."
        }

        $budgetMap[$parallelism] = $budgetPercent
    }

    return $budgetMap
}

function Parse-ScaleProfileSocketClosedFailureRateBudgets {
    param([string]$BudgetCsv)

    $budgetMap = @{}
    if ([string]::IsNullOrWhiteSpace($BudgetCsv)) {
        return $budgetMap
    }

    $tokens = $BudgetCsv.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
    foreach ($token in $tokens) {
        $entry = $token.Trim()
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        $parts = $entry.Split(':', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Length -ne 2) {
            throw "Invalid ScaleProfileSocketClosedFailureRateBudgets entry '$entry'. Expected format: parallelism:percent."
        }

        $parallelism = [int]$parts[0].Trim()
        $budgetPercent = [double]$parts[1].Trim()
        if ($parallelism -le 0) {
            throw "Invalid profile parallelism in ScaleProfileSocketClosedFailureRateBudgets entry '$entry'."
        }

        if ($budgetPercent -lt 0) {
            throw "Invalid socket-closed failure-rate budget in ScaleProfileSocketClosedFailureRateBudgets entry '$entry'. Must be >= 0."
        }

        $budgetMap[$parallelism] = $budgetPercent
    }

    return $budgetMap
}

function Parse-SocketClosedStageFailureRateBudgets {
    param([string]$BudgetCsv)

    $budgetMap = @{}
    if ([string]::IsNullOrWhiteSpace($BudgetCsv)) {
        return $budgetMap
    }

    $tokens = $BudgetCsv.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
    foreach ($token in $tokens) {
        $entry = $token.Trim()
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        $parts = $entry.Split(':', 2, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Length -ne 2) {
            throw "Invalid SocketClosedStageFailureRateBudgets entry '$entry'. Expected format: stage:percent."
        }

        $stageName = $parts[0].Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($stageName)) {
            throw "Invalid SocketClosedStageFailureRateBudgets entry '$entry'. Stage must be non-empty."
        }

        $budgetPercent = [double]$parts[1].Trim()
        if ($budgetPercent -lt 0) {
            throw "Invalid SocketClosedStageFailureRateBudgets entry '$entry'. Percent must be >= 0."
        }

        $budgetMap[$stageName] = $budgetPercent
    }

    return $budgetMap
}

function Parse-ScaleProfileSocketClosedStageFailureRateBudgets {
    param([string]$BudgetCsv)

    $budgetMap = @{}
    if ([string]::IsNullOrWhiteSpace($BudgetCsv)) {
        return $budgetMap
    }

    $tokens = $BudgetCsv.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
    foreach ($token in $tokens) {
        $entry = $token.Trim()
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        $parts = $entry.Split(':', 3, [System.StringSplitOptions]::RemoveEmptyEntries)
        if ($parts.Length -ne 3) {
            throw "Invalid ScaleProfileSocketClosedStageFailureRateBudgets entry '$entry'. Expected format: parallelism:stage:percent."
        }

        $parallelism = [int]$parts[0].Trim()
        $stageName = $parts[1].Trim().ToLowerInvariant()
        $budgetPercent = [double]$parts[2].Trim()

        if ($parallelism -le 0) {
            throw "Invalid profile parallelism in ScaleProfileSocketClosedStageFailureRateBudgets entry '$entry'."
        }

        if ([string]::IsNullOrWhiteSpace($stageName)) {
            throw "Invalid stage name in ScaleProfileSocketClosedStageFailureRateBudgets entry '$entry'."
        }

        if ($budgetPercent -lt 0) {
            throw "Invalid stage budget in ScaleProfileSocketClosedStageFailureRateBudgets entry '$entry'. Percent must be >= 0."
        }

        if (-not $budgetMap.ContainsKey($parallelism)) {
            $budgetMap[$parallelism] = @{}
        }

        $profileMap = [hashtable]$budgetMap[$parallelism]
        $profileMap[$stageName] = $budgetPercent
        $budgetMap[$parallelism] = $profileMap
    }

    return $budgetMap
}

function Get-SocketClosedStageRateSnapshotFromPerfSummary {
    param([object]$PerfSummary)

    if ($null -eq $PerfSummary) {
        return [PSCustomObject]@{
            counts = @{}
            rates_percent = @{}
            attempts_total = 0
        }
    }

    $attempts = [int](Get-NumberOrDefault -InputObject $PerfSummary -PropertyName "attempts_total" -DefaultValue 0)
    $counts = @{}
    $rates = @{}

    $stagesProp = $PerfSummary.PSObject.Properties | Where-Object { $_.Name -eq "socket_closed_failure_stages" } | Select-Object -First 1
    if ($null -ne $stagesProp -and $null -ne $stagesProp.Value) {
        foreach ($stageProp in $stagesProp.Value.PSObject.Properties) {
            $stageName = [string]$stageProp.Name
            $count = [double]$stageProp.Value
            if ([string]::IsNullOrWhiteSpace($stageName)) {
                continue
            }

            $normalizedStage = $stageName.ToLowerInvariant()
            $counts[$normalizedStage] = [int]$count
            $rates[$normalizedStage] = if ($attempts -gt 0) {
                [double][Math]::Round(($count * 100.0) / $attempts, 3)
            }
            else {
                0.0
            }
        }
    }

    return [PSCustomObject]@{
        counts = $counts
        rates_percent = $rates
        attempts_total = $attempts
    }
}

function Get-ScaleProfileRelayFailureRateEvaluation {
    param(
        [object]$ScaleSummary,
        [hashtable]$BudgetMap,
        [double]$FallbackGatePercent
    )

    if ($null -eq $ScaleSummary) {
        return [PSCustomObject]@{
            worst_rate_percent = $null
            profile_results = @()
            all_passed = $true
            failure_messages = @()
        }
    }

    $results = @($ScaleSummary.results)
    if ($results.Count -eq 0) {
        return [PSCustomObject]@{
            worst_rate_percent = $null
            profile_results = @()
            all_passed = $true
            failure_messages = @()
        }
    }

    $worst = 0.0
    $profileResults = New-Object System.Collections.Generic.List[object]
    $failureMessages = New-Object System.Collections.Generic.List[string]

    foreach ($profile in $results) {
        $parallelism = [int](Get-NumberOrDefault -InputObject $profile -PropertyName "parallelism" -DefaultValue -1)
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

        $embeddedGate = Get-NumberOrDefault -InputObject $profile -PropertyName "gate_failure_rate_pct" -DefaultValue -1
        $gatePercent = $FallbackGatePercent
        if ($parallelism -gt 0 -and $BudgetMap.ContainsKey($parallelism)) {
            $gatePercent = [double]$BudgetMap[$parallelism]
        }
        elseif ($embeddedGate -ge 0) {
            $gatePercent = [double]$embeddedGate
        }

        $passed = ($rate -le $gatePercent)
        $profileResults.Add([PSCustomObject]@{
                parallelism = $parallelism
                failure_rate_percent = [double][Math]::Round($rate, 3)
                gate_failure_rate_pct = [double][Math]::Round($gatePercent, 3)
                gate_passed = [bool]$passed
            }) | Out-Null

        if (-not $passed) {
            $failureMessages.Add(("p{0}: gate_pct={1} actual_pct={2}" -f $parallelism, $gatePercent, $rate)) | Out-Null
        }

        if ($rate -gt $worst) {
            $worst = $rate
        }
    }

    return [PSCustomObject]@{
        worst_rate_percent = [double][Math]::Round($worst, 3)
        profile_results = [object[]]$profileResults.ToArray()
        all_passed = ($failureMessages.Count -eq 0)
        failure_messages = [string[]]$failureMessages.ToArray()
    }
}

function Get-ScaleProfileSocketClosedFailureRateEvaluation {
    param(
        [object]$ScaleSummary,
        [hashtable]$BudgetMap,
        [double]$FallbackGatePercent
    )

    if ($null -eq $ScaleSummary) {
        return [PSCustomObject]@{
            worst_rate_percent = $null
            profile_results = @()
            all_passed = $true
            failure_messages = @()
        }
    }

    $results = @($ScaleSummary.results)
    if ($results.Count -eq 0) {
        return [PSCustomObject]@{
            worst_rate_percent = $null
            profile_results = @()
            all_passed = $true
            failure_messages = @()
        }
    }

    $worst = 0.0
    $profileResults = New-Object System.Collections.Generic.List[object]
    $failureMessages = New-Object System.Collections.Generic.List[string]

    foreach ($profile in $results) {
        $parallelism = [int](Get-NumberOrDefault -InputObject $profile -PropertyName "parallelism" -DefaultValue -1)
        $rate = Get-NumberOrDefault -InputObject $profile -PropertyName "socket_closed_failure_rate_percent" -DefaultValue -1
        if ($rate -lt 0) {
            $socketClosedFailures = Get-NumberOrDefault -InputObject $profile -PropertyName "socket_closed_failures" -DefaultValue 0
            $failed = Get-NumberOrDefault -InputObject $profile -PropertyName "failed_attempts" -DefaultValue 0
            $succeeded = Get-NumberOrDefault -InputObject $profile -PropertyName "successful_iterations" -DefaultValue 0
            $attempts = $failed + $succeeded
            if ($attempts -gt 0) {
                $rate = [double][Math]::Round(($socketClosedFailures * 100.0) / $attempts, 3)
            }
            else {
                $rate = 0.0
            }
        }

        $embeddedGate = Get-NumberOrDefault -InputObject $profile -PropertyName "gate_socket_closed_failure_rate_pct" -DefaultValue -1
        $gatePercent = $FallbackGatePercent
        $gateEnabled = ($FallbackGatePercent -ge 0)
        if ($parallelism -gt 0 -and $BudgetMap.ContainsKey($parallelism)) {
            $gatePercent = [double]$BudgetMap[$parallelism]
            $gateEnabled = $true
        }
        elseif ($embeddedGate -ge 0) {
            $gatePercent = [double]$embeddedGate
            $gateEnabled = $true
        }

        $passed = $true
        if ($gateEnabled) {
            $passed = ($rate -le $gatePercent)
        }

        $profileResults.Add([PSCustomObject]@{
                parallelism = $parallelism
                socket_closed_failure_rate_percent = [double][Math]::Round($rate, 3)
                gate_socket_closed_failure_rate_pct = if ($gateEnabled) { [double][Math]::Round($gatePercent, 3) } else { $null }
                gate_enabled = $gateEnabled
                gate_passed = [bool]$passed
            }) | Out-Null

        if ($gateEnabled -and -not $passed) {
            $failureMessages.Add(("p{0}: gate_pct={1} actual_pct={2}" -f $parallelism, $gatePercent, $rate)) | Out-Null
        }

        if ($rate -gt $worst) {
            $worst = $rate
        }
    }

    return [PSCustomObject]@{
        worst_rate_percent = [double][Math]::Round($worst, 3)
        profile_results = [object[]]$profileResults.ToArray()
        all_passed = ($failureMessages.Count -eq 0)
        failure_messages = [string[]]$failureMessages.ToArray()
    }
}

function Get-ScaleProfileSocketClosedStageRateEvaluation {
    param(
        [object]$ScaleSummary,
        [hashtable]$BudgetMap
    )

    if ($null -eq $ScaleSummary) {
        return [PSCustomObject]@{
            profile_results = @()
            all_passed = $true
            failure_messages = @()
        }
    }

    $results = @($ScaleSummary.results)
    if ($results.Count -eq 0) {
        return [PSCustomObject]@{
            profile_results = @()
            all_passed = $true
            failure_messages = @()
        }
    }

    $profileResults = New-Object System.Collections.Generic.List[object]
    $failureMessages = New-Object System.Collections.Generic.List[string]

    foreach ($profile in $results) {
        $parallelism = [int](Get-NumberOrDefault -InputObject $profile -PropertyName "parallelism" -DefaultValue -1)
        $attempts = [int](Get-NumberOrDefault -InputObject $profile -PropertyName "attempts_total" -DefaultValue -1)
        if ($attempts -lt 0) {
            $failed = [int](Get-NumberOrDefault -InputObject $profile -PropertyName "failed_attempts" -DefaultValue 0)
            $succeeded = [int](Get-NumberOrDefault -InputObject $profile -PropertyName "successful_iterations" -DefaultValue 0)
            $attempts = $failed + $succeeded
        }
        $attempts = [Math]::Max(0, $attempts)

        $stageCounts = @{}
        $stageRates = @{}
        $stageCountsProp = $profile.PSObject.Properties | Where-Object { $_.Name -eq "socket_closed_failure_stages" } | Select-Object -First 1
        if ($null -ne $stageCountsProp -and $null -ne $stageCountsProp.Value) {
            foreach ($stageProp in $stageCountsProp.Value.PSObject.Properties) {
                $stageNameRaw = [string]$stageProp.Name
                if ([string]::IsNullOrWhiteSpace($stageNameRaw)) {
                    continue
                }

                $stageName = $stageNameRaw.ToLowerInvariant()
                $count = [int]$stageProp.Value
                $stageCounts[$stageName] = $count
                $stageRates[$stageName] = if ($attempts -gt 0) {
                    [double][Math]::Round(($count * 100.0) / $attempts, 3)
                }
                else {
                    0.0
                }
            }
        }

        $profileBudgetMap = @{}
        if ($parallelism -gt 0 -and $BudgetMap.ContainsKey($parallelism)) {
            $profileBudgetMap = [hashtable]$BudgetMap[$parallelism]
        }

        $stageBudgetResults = New-Object System.Collections.Generic.List[object]
        $profilePassed = $true
        foreach ($stageName in $profileBudgetMap.Keys) {
            $gatePercent = [double]$profileBudgetMap[$stageName]
            $actualPercent = if ($stageRates.ContainsKey($stageName)) {
                [double]$stageRates[$stageName]
            }
            else {
                0.0
            }

            $stagePassed = ($actualPercent -le $gatePercent)
            if (-not $stagePassed) {
                $profilePassed = $false
                $failureMessages.Add(("p{0}: stage={1} gate_pct={2} actual_pct={3}" -f $parallelism, $stageName, $gatePercent, $actualPercent)) | Out-Null
            }

            $stageBudgetResults.Add([PSCustomObject]@{
                    stage = $stageName
                    stage_failure_rate_percent = [double][Math]::Round($actualPercent, 3)
                    gate_stage_failure_rate_pct = [double][Math]::Round($gatePercent, 3)
                    gate_passed = [bool]$stagePassed
                }) | Out-Null
        }

        $profileResults.Add([PSCustomObject]@{
                parallelism = $parallelism
                attempts_total = $attempts
                socket_closed_failure_stage_counts = $stageCounts
                socket_closed_failure_stage_rates_percent = $stageRates
                stage_budget_gate_enabled = ($profileBudgetMap.Count -gt 0)
                stage_budget_gate_passed = [bool]$profilePassed
                stage_budget_results = [object[]]$stageBudgetResults.ToArray()
            }) | Out-Null
    }

    return [PSCustomObject]@{
        profile_results = [object[]]$profileResults.ToArray()
        all_passed = ($failureMessages.Count -eq 0)
        failure_messages = [string[]]$failureMessages.ToArray()
    }
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
$resolvedScaleSummaryPath = if ([string]::IsNullOrWhiteSpace($ScaleSummaryPath)) { $null } else { Resolve-RepoPath -PathValue $ScaleSummaryPath }
$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

$perfSummary = Try-LoadJsonFile -PathValue $resolvedPerfSummaryPath
$scaleSummary = if ($null -eq $resolvedScaleSummaryPath) { $null } else { Try-LoadJsonFile -PathValue $resolvedScaleSummaryPath }

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

$scaleProfileRelayFailureBudgetMap = Parse-ScaleProfileRelayFailureRateBudgets -BudgetCsv $ScaleProfileRelayFailureRateBudgets
$scaleProfileSocketClosedFailureBudgetMap = Parse-ScaleProfileSocketClosedFailureRateBudgets -BudgetCsv $ScaleProfileSocketClosedFailureRateBudgets
$socketClosedStageBudgetMap = Parse-SocketClosedStageFailureRateBudgets -BudgetCsv $SocketClosedStageFailureRateBudgets
$scaleProfileSocketClosedStageBudgetMap = Parse-ScaleProfileSocketClosedStageFailureRateBudgets -BudgetCsv $ScaleProfileSocketClosedStageFailureRateBudgets
$relayRateFromPerf = Get-RelayFailureRateFromPerfSummary -PerfSummary $perfSummary
$scaleRelayRateEvaluation = Get-ScaleProfileRelayFailureRateEvaluation `
    -ScaleSummary $scaleSummary `
    -BudgetMap $scaleProfileRelayFailureBudgetMap `
    -FallbackGatePercent $MaxRelayFailureRatePercent
$socketClosedRateFromPerf = Get-SocketClosedFailureRateFromPerfSummary -PerfSummary $perfSummary
$scaleSocketClosedRateEvaluation = Get-ScaleProfileSocketClosedFailureRateEvaluation `
    -ScaleSummary $scaleSummary `
    -BudgetMap $scaleProfileSocketClosedFailureBudgetMap `
    -FallbackGatePercent $MaxSocketClosedFailureRatePercent
$scaleSocketClosedStageEvaluation = Get-ScaleProfileSocketClosedStageRateEvaluation `
    -ScaleSummary $scaleSummary `
    -BudgetMap $scaleProfileSocketClosedStageBudgetMap
$socketClosedStageSnapshot = Get-SocketClosedStageRateSnapshotFromPerfSummary -PerfSummary $perfSummary
$relayRateFromScale = $scaleRelayRateEvaluation.worst_rate_percent
$socketClosedRateFromScale = $scaleSocketClosedRateEvaluation.worst_rate_percent
$relayFailureRatePercent = 0.0
if ($null -ne $relayRateFromPerf -and $relayRateFromPerf -gt $relayFailureRatePercent) {
    $relayFailureRatePercent = $relayRateFromPerf
}

if ($null -ne $relayRateFromScale -and $relayRateFromScale -gt $relayFailureRatePercent) {
    $relayFailureRatePercent = $relayRateFromScale
}

$socketClosedFailureRatePercent = 0.0
if ($null -ne $socketClosedRateFromPerf -and $socketClosedRateFromPerf -gt $socketClosedFailureRatePercent) {
    $socketClosedFailureRatePercent = $socketClosedRateFromPerf
}

if ($null -ne $socketClosedRateFromScale -and $socketClosedRateFromScale -gt $socketClosedFailureRatePercent) {
    $socketClosedFailureRatePercent = $socketClosedRateFromScale
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
$reportSampleCount = @($reportSample).Count
$dbRate = Get-DbTimeoutRateFromReports -ReportSample $reportSample
$diagRate = Get-DiagnosticsQueueSaturationRateFromReports -ReportSample $reportSample

$gatePassed = $true
$gateReasons = New-Object System.Collections.Generic.List[string]

if ($reportSampleCount -lt $MinReportSampleSize) {
    $gatePassed = $false
    $gateReasons.Add("insufficient_report_sample: min=$MinReportSampleSize actual=$reportSampleCount") | Out-Null
}

if ($relayFailureRatePercent -gt $MaxRelayFailureRatePercent) {
    $gatePassed = $false
    $gateReasons.Add("relay_failure_rate_gate_failed: gate_pct=$MaxRelayFailureRatePercent actual_pct=$relayFailureRatePercent") | Out-Null
}

if (-not [bool]$scaleRelayRateEvaluation.all_passed) {
    $gatePassed = $false
    foreach ($failureMessage in @($scaleRelayRateEvaluation.failure_messages)) {
        $gateReasons.Add("scale_profile_relay_failure_rate_gate_failed: $failureMessage") | Out-Null
    }
}

if (($MaxSocketClosedFailureRatePercent -ge 0) -and ($socketClosedFailureRatePercent -gt $MaxSocketClosedFailureRatePercent)) {
    $gatePassed = $false
    $gateReasons.Add("socket_closed_failure_rate_gate_failed: gate_pct=$MaxSocketClosedFailureRatePercent actual_pct=$socketClosedFailureRatePercent") | Out-Null
}

if (-not [bool]$scaleSocketClosedRateEvaluation.all_passed) {
    $gatePassed = $false
    foreach ($failureMessage in @($scaleSocketClosedRateEvaluation.failure_messages)) {
        $gateReasons.Add("scale_profile_socket_closed_failure_rate_gate_failed: $failureMessage") | Out-Null
    }
}

if (-not [bool]$scaleSocketClosedStageEvaluation.all_passed) {
    $gatePassed = $false
    foreach ($failureMessage in @($scaleSocketClosedStageEvaluation.failure_messages)) {
        $gateReasons.Add("scale_profile_socket_closed_stage_failure_rate_gate_failed: $failureMessage") | Out-Null
    }
}

foreach ($stageName in $socketClosedStageBudgetMap.Keys) {
    $stageGatePercent = [double]$socketClosedStageBudgetMap[$stageName]
    $stageActualPercent = if ($socketClosedStageSnapshot.rates_percent.ContainsKey($stageName)) {
        [double]$socketClosedStageSnapshot.rates_percent[$stageName]
    }
    else {
        0.0
    }

    if ($stageActualPercent -gt $stageGatePercent) {
        $gatePassed = $false
        $gateReasons.Add("socket_closed_stage_failure_rate_gate_failed: stage=$stageName gate_pct=$stageGatePercent actual_pct=$stageActualPercent") | Out-Null
    }
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
    report_sample_size = $reportSampleCount
    report_sample_target = $reportTargetCount
    gates = [ordered]@{
        max_relay_failure_rate_percent = $MaxRelayFailureRatePercent
        scale_profile_relay_failure_rate_budgets = $ScaleProfileRelayFailureRateBudgets
        max_socket_closed_failure_rate_percent = $MaxSocketClosedFailureRatePercent
        scale_profile_socket_closed_failure_rate_budgets = $ScaleProfileSocketClosedFailureRateBudgets
        socket_closed_stage_failure_rate_budgets = $SocketClosedStageFailureRateBudgets
        scale_profile_socket_closed_stage_failure_rate_budgets = $ScaleProfileSocketClosedStageFailureRateBudgets
        max_db_timeout_rate_percent = $MaxDbTimeoutRatePercent
        max_diagnostics_queue_saturation_rate_percent = $MaxDiagnosticsQueueSaturationRatePercent
        min_report_sample_size = $MinReportSampleSize
    }
    observed = [ordered]@{
        relay_failure_rate_percent = [double][Math]::Round($relayFailureRatePercent, 3)
        relay_failure_rate_perf_percent = if ($null -eq $relayRateFromPerf) { $null } else { [double][Math]::Round($relayRateFromPerf, 3) }
        relay_failure_rate_scale_worst_profile_percent = if ($null -eq $relayRateFromScale) { $null } else { [double][Math]::Round($relayRateFromScale, 3) }
        relay_failure_rate_scale_profiles = @($scaleRelayRateEvaluation.profile_results)
        socket_closed_failure_rate_percent = [double][Math]::Round($socketClosedFailureRatePercent, 3)
        socket_closed_failure_rate_perf_percent = if ($null -eq $socketClosedRateFromPerf) { $null } else { [double][Math]::Round($socketClosedRateFromPerf, 3) }
        socket_closed_failure_rate_scale_worst_profile_percent = if ($null -eq $socketClosedRateFromScale) { $null } else { [double][Math]::Round($socketClosedRateFromScale, 3) }
        socket_closed_failure_rate_scale_profiles = @($scaleSocketClosedRateEvaluation.profile_results)
        socket_closed_failure_stage_rates_scale_profiles = @($scaleSocketClosedStageEvaluation.profile_results)
        socket_closed_failure_stage_counts_perf = $socketClosedStageSnapshot.counts
        socket_closed_failure_stage_rates_perf = $socketClosedStageSnapshot.rates_percent
        socket_closed_failure_stage_attempts_perf = [int]$socketClosedStageSnapshot.attempts_total
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
