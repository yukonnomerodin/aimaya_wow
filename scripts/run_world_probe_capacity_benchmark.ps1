param(
    [string]$ScaleProfilesScriptPath = "scripts/run_world_probe_scale_profiles.ps1",
    [string]$StartGatewaysScriptPath = "scripts/start_retail_gateways.ps1",
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$SummaryPath = "docs/handshake/runlogs/probe_capacity_benchmark.latest.json",
    [string]$HypothesisId = "",
    [int]$Rounds = 3,
    [int]$IterationsPerProfile = 12,
    [int]$AllowFailuresPerProfile = -1,
    [string]$Profiles = "1,4,8,16,32",
    [double]$P95SafetyMultiplier = 1.20,
    [double]$MaxSafetyMultiplier = 1.15,
    [double]$FailureRateSafetyDeltaPercent = 2.0,
    [double]$SocketClosedFailureRateSafetyDeltaPercent = 1.0,
    [double]$MaxFailureRatePctP1 = 8.0,
    [double]$MaxFailureRatePctP4 = 10.0,
    [double]$MaxFailureRatePctP8 = 15.0,
    [double]$MaxFailureRatePctP16 = 24.0,
    [double]$MaxFailureRatePctP32 = 28.0,
    [double]$MaxSocketClosedFailureRatePctP1 = 6.0,
    [double]$MaxSocketClosedFailureRatePctP4 = 8.0,
    [double]$MaxSocketClosedFailureRatePctP8 = 12.0,
    [double]$MaxSocketClosedFailureRatePctP16 = 18.0,
    [double]$MaxSocketClosedFailureRatePctP32 = 24.0,
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

function Resolve-ProfileList {
    param([string]$ProfilesCsv)

    $profiles = @($ProfilesCsv.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object { [int]$_.Trim() } |
        Select-Object -Unique)

    if ($profiles.Count -eq 0) {
        throw "Profiles list is empty."
    }

    foreach ($profile in $profiles) {
        if ($profile -le 0) {
            throw "Profile parallelism must be > 0: $profile"
        }
    }

    return [int[]]$profiles
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

function Get-ConfiguredFailureRateGateForProfile {
    param([int]$Parallelism)

    switch ($Parallelism) {
        1 { return [double]$MaxFailureRatePctP1 }
        4 { return [double]$MaxFailureRatePctP4 }
        8 { return [double]$MaxFailureRatePctP8 }
        16 { return [double]$MaxFailureRatePctP16 }
        32 { return [double]$MaxFailureRatePctP32 }
        default { return -1.0 }
    }
}

function Get-ConfiguredSocketClosedFailureRateGateForProfile {
    param([int]$Parallelism)

    switch ($Parallelism) {
        1 { return [double]$MaxSocketClosedFailureRatePctP1 }
        4 { return [double]$MaxSocketClosedFailureRatePctP4 }
        8 { return [double]$MaxSocketClosedFailureRatePctP8 }
        16 { return [double]$MaxSocketClosedFailureRatePctP16 }
        32 { return [double]$MaxSocketClosedFailureRatePctP32 }
        default { return -1.0 }
    }
}

if ($Rounds -le 0) { throw "Rounds must be > 0." }
if ($IterationsPerProfile -le 0) { throw "IterationsPerProfile must be > 0." }
if ($AllowFailuresPerProfile -lt -1) { throw "AllowFailuresPerProfile must be >= -1 (-1 means auto from failure-rate gate)." }
if ($P95SafetyMultiplier -lt 1.0) { throw "P95SafetyMultiplier must be >= 1.0." }
if ($MaxSafetyMultiplier -lt 1.0) { throw "MaxSafetyMultiplier must be >= 1.0." }
if ($FailureRateSafetyDeltaPercent -lt 0) { throw "FailureRateSafetyDeltaPercent must be >= 0." }
if ($SocketClosedFailureRateSafetyDeltaPercent -lt 0) { throw "SocketClosedFailureRateSafetyDeltaPercent must be >= 0." }

$profileList = Resolve-ProfileList -ProfilesCsv $Profiles
$resolvedScaleProfilesScriptPath = Resolve-RepoPath -PathValue $ScaleProfilesScriptPath
$resolvedStartGatewaysScriptPath = Resolve-RepoPath -PathValue $StartGatewaysScriptPath
$resolvedRunlogsPath = Resolve-RepoPath -PathValue $RunlogsPath
$resolvedSummaryPath = Resolve-RepoPath -PathValue $SummaryPath

if (-not (Test-Path $resolvedScaleProfilesScriptPath)) {
    throw "Scale profiles script not found: $resolvedScaleProfilesScriptPath"
}

if ($AutoStartGateways -and -not (Test-Path $resolvedStartGatewaysScriptPath)) {
    throw "Start gateways script not found: $resolvedStartGatewaysScriptPath"
}

New-Item -ItemType Directory -Path $resolvedRunlogsPath -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Path $resolvedSummaryPath -Parent) -Force | Out-Null

if ($AutoStartGateways) {
    $startArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $resolvedStartGatewaysScriptPath)
    if (-not [string]::IsNullOrWhiteSpace($HypothesisId)) {
        $startArgs += @("-HypothesisId", $HypothesisId)
    }

    & powershell @startArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start gateways before capacity benchmark."
    }
}

$startedAt = [DateTimeOffset]::UtcNow
$roundSummaries = New-Object System.Collections.Generic.List[object]
$profileStats = @{}

for ($round = 1; $round -le $Rounds; $round++) {
    $roundSummaryPath = Join-Path $resolvedRunlogsPath ("probe_scale_profiles.benchmark_round_{0}.json" -f $round)
    $raw = & powershell -NoProfile -ExecutionPolicy Bypass -File $resolvedScaleProfilesScriptPath `
        -HypothesisId $HypothesisId `
        -IterationsPerProfile $IterationsPerProfile `
        -AllowFailuresPerProfile $AllowFailuresPerProfile `
        -Profiles $Profiles `
        -SummaryPath $roundSummaryPath `
        -MaxFailureRatePctP1 $MaxFailureRatePctP1 `
        -MaxFailureRatePctP4 $MaxFailureRatePctP4 `
        -MaxFailureRatePctP8 $MaxFailureRatePctP8 `
        -MaxFailureRatePctP16 $MaxFailureRatePctP16 `
        -MaxFailureRatePctP32 $MaxFailureRatePctP32

    $scaleExitCode = $LASTEXITCODE
    $roundSummary = Try-LoadJsonFile -PathValue $roundSummaryPath
    $roundOverallPass = if ($null -eq $roundSummary) { $false } else { [bool]$roundSummary.overall_pass }

    $roundSummaries.Add([PSCustomObject]@{
            round = $round
            exit_code = $scaleExitCode
            overall_pass = $roundOverallPass
            summary_path = $roundSummaryPath
        }) | Out-Null

    if ($null -eq $roundSummary) {
        continue
    }

    foreach ($result in @($roundSummary.results)) {
        $parallelism = [int]$result.parallelism
        if ($parallelism -le 0) {
            continue
        }

        if (-not $profileStats.ContainsKey($parallelism)) {
            $profileStats[$parallelism] = [PSCustomObject]@{
                p50_values = New-Object System.Collections.Generic.List[double]
                p95_values = New-Object System.Collections.Generic.List[double]
                max_values = New-Object System.Collections.Generic.List[double]
                failure_rate_values = New-Object System.Collections.Generic.List[double]
                socket_closed_failure_rate_values = New-Object System.Collections.Generic.List[double]
                socket_closed_failure_stage_counts = @{}
            }
        }

        $stats = $profileStats[$parallelism]
        $stats.p50_values.Add([double]$result.p50_ms) | Out-Null
        $stats.p95_values.Add([double]$result.p95_ms) | Out-Null
        $stats.max_values.Add([double]$result.max_ms) | Out-Null
        $stats.failure_rate_values.Add([double]$result.failure_rate_percent) | Out-Null

        $socketClosedRate = if ($null -ne $result.socket_closed_failure_rate_percent) {
            [double]$result.socket_closed_failure_rate_percent
        }
        else {
            0.0
        }
        $stats.socket_closed_failure_rate_values.Add($socketClosedRate) | Out-Null

        $stageCountsProp = $result.PSObject.Properties | Where-Object { $_.Name -eq "socket_closed_failure_stages" } | Select-Object -First 1
        if ($null -ne $stageCountsProp -and $null -ne $stageCountsProp.Value) {
            foreach ($stageProp in $stageCountsProp.Value.PSObject.Properties) {
                $stageName = [string]$stageProp.Name
                if ([string]::IsNullOrWhiteSpace($stageName)) {
                    continue
                }

                $normalizedStage = $stageName.ToLowerInvariant()
                $stageCount = [int]$stageProp.Value
                if (-not $stats.socket_closed_failure_stage_counts.ContainsKey($normalizedStage)) {
                    $stats.socket_closed_failure_stage_counts[$normalizedStage] = 0
                }

                $stats.socket_closed_failure_stage_counts[$normalizedStage] += $stageCount
            }
        }
    }
}

$recommendations = New-Object System.Collections.Generic.List[object]
foreach ($parallelism in $profileList) {
    if (-not $profileStats.ContainsKey($parallelism)) {
        continue
    }

    $stats = $profileStats[$parallelism]
    if ($stats.p95_values.Count -eq 0 -or $stats.max_values.Count -eq 0 -or $stats.failure_rate_values.Count -eq 0) {
        continue
    }

    $worstP50 = [double](($stats.p50_values | Measure-Object -Maximum).Maximum)
    $worstP95 = [double](($stats.p95_values | Measure-Object -Maximum).Maximum)
    $worstMax = [double](($stats.max_values | Measure-Object -Maximum).Maximum)
    $worstFailureRate = [double](($stats.failure_rate_values | Measure-Object -Maximum).Maximum)
    $worstSocketClosedFailureRate = if ($stats.socket_closed_failure_rate_values.Count -gt 0) {
        [double](($stats.socket_closed_failure_rate_values | Measure-Object -Maximum).Maximum)
    }
    else {
        0.0
    }

    $recommendedP95 = [int][Math]::Ceiling($worstP95 * $P95SafetyMultiplier)
    $recommendedMaxRaw = [int][Math]::Ceiling($worstMax * $MaxSafetyMultiplier)
    $recommendedMax = [Math]::Max($recommendedP95, $recommendedMaxRaw)
    $configuredFailureRateGate = Get-ConfiguredFailureRateGateForProfile -Parallelism $parallelism
    $recommendedFailureRateRaw = [double][Math]::Round([Math]::Min(100.0, ($worstFailureRate + $FailureRateSafetyDeltaPercent)), 3)
    $recommendedFailureRate = if ($configuredFailureRateGate -ge 0) {
        [double][Math]::Round([Math]::Min($configuredFailureRateGate, $recommendedFailureRateRaw), 3)
    }
    else {
        $recommendedFailureRateRaw
    }
    $configuredSocketClosedFailureRateGate = Get-ConfiguredSocketClosedFailureRateGateForProfile -Parallelism $parallelism
    $recommendedSocketClosedFailureRateRaw = [double][Math]::Round(
        [Math]::Min(100.0, ($worstSocketClosedFailureRate + $SocketClosedFailureRateSafetyDeltaPercent)),
        3)
    $recommendedSocketClosedFailureRate = if ($configuredSocketClosedFailureRateGate -ge 0) {
        [double][Math]::Round([Math]::Min($configuredSocketClosedFailureRateGate, $recommendedSocketClosedFailureRateRaw), 3)
    }
    else {
        $recommendedSocketClosedFailureRateRaw
    }

    $stageCounts = @{}
    foreach ($stageKey in $stats.socket_closed_failure_stage_counts.Keys) {
        $stageCounts[$stageKey] = [int]$stats.socket_closed_failure_stage_counts[$stageKey]
    }

    $totalSocketClosedStageCount = 0
    foreach ($countValue in $stageCounts.Values) {
        $totalSocketClosedStageCount += [int]$countValue
    }

    $stageSharePercent = @{}
    $dominantStage = ""
    $dominantStageCount = 0
    foreach ($stageKey in $stageCounts.Keys) {
        $countValue = [int]$stageCounts[$stageKey]
        if ($countValue -gt $dominantStageCount) {
            $dominantStageCount = $countValue
            $dominantStage = $stageKey
        }

        $stageSharePercent[$stageKey] = if ($totalSocketClosedStageCount -gt 0) {
            [double][Math]::Round(($countValue * 100.0) / $totalSocketClosedStageCount, 3)
        }
        else {
            0.0
        }
    }

    $recommendations.Add([PSCustomObject]@{
            parallelism = $parallelism
            observed_worst_p50_ms = [double][Math]::Round($worstP50, 3)
            observed_worst_p95_ms = [double][Math]::Round($worstP95, 3)
            observed_worst_max_ms = [double][Math]::Round($worstMax, 3)
            observed_worst_failure_rate_percent = [double][Math]::Round($worstFailureRate, 3)
            observed_worst_socket_closed_failure_rate_percent = [double][Math]::Round($worstSocketClosedFailureRate, 3)
            configured_failure_rate_gate_percent = if ($configuredFailureRateGate -lt 0) { $null } else { [double][Math]::Round($configuredFailureRateGate, 3) }
            configured_socket_closed_failure_rate_gate_percent = if ($configuredSocketClosedFailureRateGate -lt 0) { $null } else { [double][Math]::Round($configuredSocketClosedFailureRateGate, 3) }
            recommended_p95_gate_ms = $recommendedP95
            recommended_max_gate_ms = $recommendedMax
            recommended_failure_rate_gate_percent_raw = $recommendedFailureRateRaw
            recommended_failure_rate_gate_percent = $recommendedFailureRate
            recommended_socket_closed_failure_rate_gate_percent_raw = $recommendedSocketClosedFailureRateRaw
            recommended_socket_closed_failure_rate_gate_percent = $recommendedSocketClosedFailureRate
            socket_closed_failure_stage_counts = $stageCounts
            socket_closed_failure_stage_share_percent = $stageSharePercent
            dominant_socket_closed_stage = if ([string]::IsNullOrWhiteSpace($dominantStage)) { $null } else { $dominantStage }
            dominant_socket_closed_stage_share_percent = if ([string]::IsNullOrWhiteSpace($dominantStage) -or -not $stageSharePercent.ContainsKey($dominantStage)) { $null } else { [double]$stageSharePercent[$dominantStage] }
        }) | Out-Null
}

$finishedAt = [DateTimeOffset]::UtcNow
$summary = [ordered]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    hypothesis_id = $HypothesisId
    rounds_requested = $Rounds
    rounds_completed = $roundSummaries.Count
    iterations_per_profile = $IterationsPerProfile
    allow_failures_per_profile = $AllowFailuresPerProfile
    profiles = @($profileList)
    safety = [ordered]@{
        p95_multiplier = $P95SafetyMultiplier
        max_multiplier = $MaxSafetyMultiplier
        failure_rate_delta_percent = $FailureRateSafetyDeltaPercent
        socket_closed_failure_rate_delta_percent = $SocketClosedFailureRateSafetyDeltaPercent
    }
    round_summaries = [object[]]$roundSummaries.ToArray()
    recommendations = [object[]]$recommendations.ToArray()
    duration_total_ms = [Math]::Max(0, [int]($finishedAt - $startedAt).TotalMilliseconds)
}

$summaryJson = $summary | ConvertTo-Json -Depth 10
$summaryJson | Set-Content -Path $resolvedSummaryPath -Encoding UTF8
$summaryJson

if ($recommendations.Count -eq 0) {
    exit 1
}
