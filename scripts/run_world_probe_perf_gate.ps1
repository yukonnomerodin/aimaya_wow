param(
    [string]$ProbeScriptPath = "scripts/invoke_synthetic_world_probe.ps1",
    [string]$StartGatewaysScriptPath = "scripts/start_retail_gateways.ps1",
    [string]$ServerHost = "127.0.0.1",
    [int]$Port = 8086,
    [int]$AccountId = 1,
    [int]$Iterations = 30,
    [int]$Parallelism = 4,
    [int]$AllowFailures = 4,
    [int]$DispatchStaggerMs = 50,
    [int]$ProbeConnectTimeoutMs = 4000,
    [int]$ProbeReadTimeoutMs = 4000,
    [int]$ProbePostAckReadFrames = 8,
    [int]$ProbePostAckReadTimeoutMs = 250,
    [int]$ProbePostAckWaitMs = 100,
    [int]$RetryOnSocketClosedCount = 1,
    [int]$P50GateMs = 0,
    [int]$P95GateMs = 0,
    [int]$MaxDurationGateMs = 0,
    [double]$MaxFailureRatePercent = -1,
    [switch]$AutoStartGateways,
    [string]$HypothesisId = "",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_perf_gate.latest.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RepoPath {
    param([string]$PathValue)

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $PathValue))
}

function Get-PercentileValue {
    param(
        [double[]]$SortedValues,
        [double]$Percentile
    )

    if ($null -eq $SortedValues -or $SortedValues.Length -eq 0) {
        return $null
    }

    $p = [Math]::Min(1.0, [Math]::Max(0.0, $Percentile))
    $index = [int][Math]::Floor(($SortedValues.Length - 1) * $p)
    return [double]$SortedValues[$index]
}

function Resolve-FailureBucketName {
    param([string]$ErrorText)

    if ([string]::IsNullOrWhiteSpace($ErrorText)) {
        return "unknown"
    }

    $normalized = $ErrorText.ToLowerInvariant()
    if ($normalized.Contains("endconnect") -or $normalized.Contains("connect")) {
        return "connect_refused_or_unreachable"
    }

    if ($normalized.Contains("socket closed")) {
        return "socket_closed_during_read"
    }

    if ($normalized.Contains("timeout")) {
        return "timeout"
    }

    if ($normalized.Contains("job state is failed")) {
        return "probe_job_failed"
    }

    return "other"
}

if ($Iterations -le 0) { throw "Iterations must be > 0." }
if ($Parallelism -le 0) { throw "Parallelism must be > 0." }
if ($AllowFailures -lt 0) { throw "AllowFailures must be >= 0." }

$resolvedProbeScript = Resolve-RepoPath -PathValue $ProbeScriptPath
if (-not (Test-Path $resolvedProbeScript)) {
    throw "Probe script not found: $resolvedProbeScript"
}

$resolvedStartGatewaysScript = Resolve-RepoPath -PathValue $StartGatewaysScriptPath
if ($AutoStartGateways -and -not (Test-Path $resolvedStartGatewaysScript)) {
    throw "Start script not found: $resolvedStartGatewaysScript"
}

$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

if ($AutoStartGateways) {
    $startArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $resolvedStartGatewaysScript
    )

    if (-not [string]::IsNullOrWhiteSpace($HypothesisId)) {
        $startArgs += @("-HypothesisId", $HypothesisId)
    }

    & powershell @startArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start retail gateways."
    }
}

$targetSuccessCount = $Iterations
$maxAttemptCount = $Iterations + $AllowFailures
$runningJobs = New-Object System.Collections.Generic.List[System.Management.Automation.Job]
$successRows = New-Object System.Collections.Generic.List[object]
$failureRows = New-Object System.Collections.Generic.List[object]
$attemptId = 0
$startedAt = [DateTimeOffset]::UtcNow

try {
    while (($successRows.Count -lt $targetSuccessCount) -and (($attemptId -lt $maxAttemptCount) -or ($runningJobs.Count -gt 0))) {
        while (($runningJobs.Count -lt $Parallelism) -and ($attemptId -lt $maxAttemptCount) -and (($successRows.Count + $runningJobs.Count) -lt $targetSuccessCount)) {
            $attemptId++
            $localAttemptId = $attemptId
            $job = Start-Job -Name ("probe-{0}" -f $localAttemptId) -ScriptBlock {
                param(
                    [int]$AttemptId,
                    [string]$ResolvedProbeScript,
                    [string]$ServerHost,
                    [int]$Port,
                    [int]$AccountId,
                    [int]$ConnectTimeoutMs,
                    [int]$ReadTimeoutMs,
                    [int]$PostAckReadFrames,
                    [int]$PostAckReadTimeoutMs,
                    [int]$PostAckWaitMs,
                    [int]$RetryOnSocketClosedCount
                )

                Set-StrictMode -Version Latest
                $ErrorActionPreference = "Stop"

                $maxProbeAttempts = 1 + [Math]::Max(0, $RetryOnSocketClosedCount)
                $lastProbeError = $null
                for ($probeAttempt = 1; $probeAttempt -le $maxProbeAttempts; $probeAttempt++) {
                    try {
                        $probeOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $ResolvedProbeScript `
                            -ServerHost $ServerHost `
                            -Port $Port `
                            -AccountId $AccountId `
                            -ConnectTimeoutMs $ConnectTimeoutMs `
                            -ReadTimeoutMs $ReadTimeoutMs `
                            -PostAckReadFrames $PostAckReadFrames `
                            -PostAckReadTimeoutMs $PostAckReadTimeoutMs `
                            -PostAckWaitMs $PostAckWaitMs

                        $probeJson = ($probeOutput -join "`n") | ConvertFrom-Json
                        $postAckOpcodes = @($probeJson.post_ack_observed_opcodes)
                        return [PSCustomObject]@{
                            attempt_id = $AttemptId
                            duration_ms = [double]$probeJson.duration_ms
                            ack_sent = [bool]$probeJson.ack_sent
                            enter_encrypted_seen = [bool]$probeJson.enter_encrypted_seen
                            post_ack_opcode_count = $postAckOpcodes.Count
                            probe_retry_count = $probeAttempt - 1
                        }
                    }
                    catch {
                        $lastProbeError = $_.Exception.Message
                        $normalized = $lastProbeError.ToLowerInvariant()
                        $isSocketClosedTransient = $normalized.Contains("socket closed while reading")
                        if ($isSocketClosedTransient -and $probeAttempt -lt $maxProbeAttempts) {
                            Start-Sleep -Milliseconds 40
                            continue
                        }

                        throw
                    }
                }

                throw "Probe failed after $maxProbeAttempts attempts. LastError=$lastProbeError"
            } -ArgumentList @(
                $localAttemptId,
                $resolvedProbeScript,
                $ServerHost,
                $Port,
                $AccountId,
                $ProbeConnectTimeoutMs,
                $ProbeReadTimeoutMs,
                $ProbePostAckReadFrames,
                $ProbePostAckReadTimeoutMs,
                $ProbePostAckWaitMs,
                $RetryOnSocketClosedCount
            )

            $runningJobs.Add($job) | Out-Null

            if ($DispatchStaggerMs -gt 0) {
                Start-Sleep -Milliseconds $DispatchStaggerMs
            }
        }

        if ($runningJobs.Count -eq 0) {
            break
        }

        $completedJob = Wait-Job -Job $runningJobs -Any -Timeout 2
        if ($null -eq $completedJob) {
            continue
        }

        $null = $runningJobs.Remove($completedJob)
        try {
            if ($completedJob.State -ne 'Completed') {
                $reason = if ($null -ne $completedJob.ChildJobs -and $completedJob.ChildJobs.Count -gt 0) {
                    $completedJob.ChildJobs[0].JobStateInfo.Reason
                }
                else {
                    $null
                }

                throw "Job state is $($completedJob.State). Reason=$reason"
            }

            $jobResult = Receive-Job -Job $completedJob -ErrorAction Stop | Select-Object -Last 1
            if ($null -eq $jobResult) {
                throw "Job returned empty result."
            }

            $successRows.Add([PSCustomObject]@{
                    attempt_id = [int]$jobResult.attempt_id
                    duration_ms = [double]$jobResult.duration_ms
                    ack_sent = [bool]$jobResult.ack_sent
                    enter_encrypted_seen = [bool]$jobResult.enter_encrypted_seen
                    post_ack_opcode_count = [int]$jobResult.post_ack_opcode_count
                    probe_retry_count = [int]$jobResult.probe_retry_count
                }) | Out-Null
        }
        catch {
            $jobAttemptId = if ($completedJob.Name -match '^probe-(\d+)$') { [int]$Matches[1] } else { $attemptId }
            $failureRows.Add([PSCustomObject]@{
                    attempt_id = $jobAttemptId
                    error = $_.Exception.Message
                }) | Out-Null
        }
        finally {
            Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue
        }
    }
}
finally {
    foreach ($job in @($runningJobs)) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        catch {
        }
    }
}

$durations = @($successRows | ForEach-Object { [double]$_.duration_ms } | Sort-Object)
$durationArray = [double[]]$durations
$successCount = $successRows.Count
$failureCount = $failureRows.Count
$attemptsTotal = $attemptId
$failureRatePercent = if ($attemptsTotal -gt 0) {
    [double][Math]::Round(($failureCount * 100.0) / $attemptsTotal, 3)
}
else {
    0.0
}
$finishedAt = [DateTimeOffset]::UtcNow

$p50 = Get-PercentileValue -SortedValues $durationArray -Percentile 0.50
$p95 = Get-PercentileValue -SortedValues $durationArray -Percentile 0.95
$avg = if ($successCount -gt 0) { [double][Math]::Round((($durationArray | Measure-Object -Average).Average), 2) } else { $null }
$min = if ($successCount -gt 0) { [double]$durationArray[0] } else { $null }
$max = if ($successCount -gt 0) { [double]$durationArray[$durationArray.Length - 1] } else { $null }

$gatePassed = $true
$gateReasons = New-Object System.Collections.Generic.List[string]

if ($successCount -lt $targetSuccessCount) {
    $gatePassed = $false
    $gateReasons.Add("insufficient_successful_probes: expected=$targetSuccessCount got=$successCount") | Out-Null
}

if ($failureCount -gt $AllowFailures) {
    $gatePassed = $false
    $gateReasons.Add("failure_budget_exceeded: allowed=$AllowFailures got=$failureCount") | Out-Null
}

if (($MaxFailureRatePercent -ge 0) -and ($failureRatePercent -gt $MaxFailureRatePercent)) {
    $gatePassed = $false
    $gateReasons.Add("failure_rate_gate_failed: gate_pct=$MaxFailureRatePercent actual_pct=$failureRatePercent") | Out-Null
}

if (($P50GateMs -gt 0) -and ($null -ne $p50) -and ($p50 -gt $P50GateMs)) {
    $gatePassed = $false
    $gateReasons.Add("p50_gate_failed: gate_ms=$P50GateMs actual_ms=$p50") | Out-Null
}

if (($P95GateMs -gt 0) -and ($null -ne $p95) -and ($p95 -gt $P95GateMs)) {
    $gatePassed = $false
    $gateReasons.Add("p95_gate_failed: gate_ms=$P95GateMs actual_ms=$p95") | Out-Null
}

if (($MaxDurationGateMs -gt 0) -and ($null -ne $max) -and ($max -gt $MaxDurationGateMs)) {
    $gatePassed = $false
    $gateReasons.Add("max_duration_gate_failed: gate_ms=$MaxDurationGateMs actual_ms=$max") | Out-Null
}

$gateReasonArray = [string[]]$gateReasons.ToArray()
$failureArray = [object[]]$failureRows.ToArray()
$failureBucketCounts = @{}
foreach ($failure in $failureRows) {
    $bucket = Resolve-FailureBucketName -ErrorText ([string]$failure.error)
    if (-not $failureBucketCounts.ContainsKey($bucket)) {
        $failureBucketCounts[$bucket] = 0
    }

    $failureBucketCounts[$bucket]++
}

$summary = [ordered]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    server_host = $ServerHost
    port = $Port
    account_id = $AccountId
    hypothesis_id = $HypothesisId
    target_iterations = $targetSuccessCount
    parallelism = $Parallelism
    allow_failures = $AllowFailures
    retry_on_socket_closed_count = $RetryOnSocketClosedCount
    attempts_total = $attemptId
    successful_iterations = $successCount
    failed_attempts = $failureCount
    failure_rate_percent = $failureRatePercent
    min_ms = $min
    p50_ms = $p50
    p95_ms = $p95
    avg_ms = $avg
    max_ms = $max
    durations_ms = $durationArray
    gate_passed = $gatePassed
    gate_reasons = $gateReasonArray
    failure_buckets = $failureBucketCounts
    failures = $failureArray
    duration_total_ms = [Math]::Max(0, [int]($finishedAt - $startedAt).TotalMilliseconds)
}

$summaryJson = ($summary | ConvertTo-Json -Depth 8)
$summaryJson | Set-Content -Path $resolvedSummaryPath -Encoding UTF8
$summaryJson

if (-not $gatePassed) {
    exit 1
}
