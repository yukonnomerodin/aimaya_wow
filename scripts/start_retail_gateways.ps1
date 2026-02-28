param(
    [string]$HypothesisId = "",
    [int]$AuthPort = 1119,
    [int]$WorldPort = 8086,
    [int]$StartupTimeoutSeconds = 15,
    [int]$StartupRetryCount = 2,
    [int]$StartupRetryBackoffMs = 750,
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [bool]$ForceReleasePorts = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent $scriptRoot

function Resolve-RepoPath([string]$PathValue) {
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return [System.IO.Path]::GetFullPath($PathValue)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $PathValue))
}

function Stop-IfRunning([string]$ProcessName) {
    Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Stop-GatewayDotnetHosts {
    $gatewayDotnet = Get-CimInstance Win32_Process -Filter "Name = 'dotnet.exe'" -ErrorAction SilentlyContinue |
        Where-Object {
            $cmd = [string]$_.CommandLine
            $cmd -like "*Adapter.AuthGateway.dll*" -or $cmd -like "*Adapter.WorldGateway.dll*"
        }

    foreach ($proc in $gatewayDotnet) {
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            Write-Output ("[start_retail_gateways] stopped stale dotnet gateway host pid={0}" -f $proc.ProcessId)
        } catch {
            # Ignore races (process exited between query and stop); assert-port step will validate final state.
        }
    }
}

function Stop-ListenersOnPort([int]$Port) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    foreach ($listener in $listeners) {
        try {
            Stop-Process -Id $listener.OwningProcess -Force -ErrorAction Stop
            Write-Output ("[start_retail_gateways] released port {0} by stopping pid={1}" -f $Port, $listener.OwningProcess)
        } catch {
            # Ignore races; final Assert-PortFree call is authoritative.
        }
    }
}

function Assert-PortFree([int]$Port) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($listeners) {
        $owners = @()
        foreach ($listener in $listeners) {
            $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                $owners += ("{0}({1})" -f $proc.ProcessName, $proc.Id)
            } else {
                $owners += ("pid={0}" -f $listener.OwningProcess)
            }
        }

        throw "Port $Port is already in LISTEN by: $($owners -join ', ')."
    }
}

function Wait-Listener([int]$Port, [int]$ProcessId, [int]$TimeoutSec) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -eq $ProcessId } |
            Select-Object -First 1 LocalAddress, LocalPort, OwningProcess, State
        if ($listener) {
            return $listener
        }

        Start-Sleep -Milliseconds 200
    }

    return $null
}

function Read-LogTail([string]$Path, [int]$Lines = 80) {
    if (-not (Test-Path $Path)) {
        return "<log_missing:$Path>"
    }

    try {
        return ((Get-Content -Path $Path -Tail $Lines) -join [Environment]::NewLine)
    }
    catch {
        return "<log_read_failed:$Path>"
    }
}

function Start-GatewayWithRetry {
    param(
        [string]$GatewayName,
        [string]$DotnetHost,
        [string]$DllPath,
        [string]$WorkingDirectory,
        [int]$Port,
        [int]$TimeoutSeconds,
        [int]$RetryCount,
        [int]$RetryBackoffMs,
        [string]$RunlogsDirectory,
        [bool]$ForceReleasePort
    )

    $totalAttempts = $RetryCount + 1
    $attemptDetails = New-Object System.Collections.Generic.List[string]

    for ($attempt = 1; $attempt -le $totalAttempts; $attempt++) {
        $attemptStamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ").ToLowerInvariant()
        $stdoutPath = Join-Path $RunlogsDirectory ("{0}.retail_run.{1}.attempt{2}.stdout.log" -f $GatewayName.ToLowerInvariant(), $attemptStamp, $attempt)
        $stderrPath = Join-Path $RunlogsDirectory ("{0}.retail_run.{1}.attempt{2}.stderr.log" -f $GatewayName.ToLowerInvariant(), $attemptStamp, $attempt)
        $proc = $null
        $keepProcessAlive = $false

        try {
            if ($ForceReleasePort) {
                Stop-ListenersOnPort -Port $Port
                Start-Sleep -Milliseconds 120
            }

            Assert-PortFree -Port $Port

            $proc = Start-Process -FilePath $DotnetHost -ArgumentList @($DllPath) -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
            $listener = Wait-Listener -Port $Port -ProcessId $proc.Id -TimeoutSec $TimeoutSeconds
            if ($listener) {
                $keepProcessAlive = $true
                return [PSCustomObject]@{
                    process = $proc
                    listener = $listener
                    stdout = $stdoutPath
                    stderr = $stderrPath
                    attempts_used = $attempt
                }
            }

            $stdoutTail = Read-LogTail -Path $stdoutPath -Lines 120
            $stderrTail = Read-LogTail -Path $stderrPath -Lines 120
            $attemptDetails.Add("attempt=$attempt; pid=$($proc.Id); listener_timeout=${TimeoutSeconds}s; stdout_tail=`n$stdoutTail`nstderr_tail=`n$stderrTail") | Out-Null
        }
        catch {
            $attemptDetails.Add("attempt=$attempt; error=$($_.Exception.Message)") | Out-Null
        }
        finally {
            if (($null -ne $proc) -and (-not $keepProcessAlive)) {
                try {
                    if (-not $proc.HasExited) {
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                }
            }

            if ($ForceReleasePort -and (-not $keepProcessAlive)) {
                Stop-ListenersOnPort -Port $Port
            }
        }

        if ($attempt -lt $totalAttempts -and $RetryBackoffMs -gt 0) {
            Start-Sleep -Milliseconds $RetryBackoffMs
        }
    }

    $details = $attemptDetails -join ([Environment]::NewLine + "-----" + [Environment]::NewLine)
    throw "$GatewayName failed to listen on port $Port after $totalAttempts attempts.`n$details"
}

function Sync-IfExists([string]$SourcePath, [string]$DestinationPath) {
    if (-not (Test-Path $SourcePath)) {
        return
    }

    Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
    Write-Output ("[start_retail_gateways] synced config {0} -> {1}" -f $SourcePath, $DestinationPath)
}

$runlogs = Resolve-RepoPath $RunlogsPath
New-Item -ItemType Directory -Path $runlogs -Force | Out-Null

$authWorkDir = Resolve-RepoPath "src/Adapter.AuthGateway/bin/Debug/net8.0"
$worldWorkDir = Resolve-RepoPath "src/Adapter.WorldGateway/bin/Debug/net8.0"
$authSourceAppSettings = Resolve-RepoPath "src/Adapter.AuthGateway/appsettings.json"
$worldSourceAppSettings = Resolve-RepoPath "src/Adapter.WorldGateway/appsettings.json"
$authRuntimeAppSettings = Join-Path $authWorkDir "appsettings.json"
$worldRuntimeAppSettings = Join-Path $worldWorkDir "appsettings.json"
$authDll = Join-Path $authWorkDir "Adapter.AuthGateway.dll"
$worldDll = Join-Path $worldWorkDir "Adapter.WorldGateway.dll"
$dotnetHost = "dotnet"

if (-not (Test-Path $authDll)) {
    throw "AuthGateway assembly not found: $authDll"
}

if (-not (Test-Path $worldDll)) {
    throw "WorldGateway assembly not found: $worldDll"
}

if ($StartupRetryCount -lt 0) {
    throw "StartupRetryCount must be >= 0."
}

Sync-IfExists -SourcePath $authSourceAppSettings -DestinationPath $authRuntimeAppSettings
Sync-IfExists -SourcePath $worldSourceAppSettings -DestinationPath $worldRuntimeAppSettings

Stop-IfRunning -ProcessName "Adapter.AuthGateway"
Stop-IfRunning -ProcessName "Adapter.WorldGateway"
Stop-GatewayDotnetHosts
Start-Sleep -Milliseconds 300

if ($ForceReleasePorts) {
    Stop-ListenersOnPort -Port $AuthPort
    Stop-ListenersOnPort -Port $WorldPort
    Start-Sleep -Milliseconds 200
}

$authStart = Start-GatewayWithRetry `
    -GatewayName "AuthGateway" `
    -DotnetHost $dotnetHost `
    -DllPath $authDll `
    -WorkingDirectory $authWorkDir `
    -Port $AuthPort `
    -TimeoutSeconds $StartupTimeoutSeconds `
    -RetryCount $StartupRetryCount `
    -RetryBackoffMs $StartupRetryBackoffMs `
    -RunlogsDirectory $runlogs `
    -ForceReleasePort $ForceReleasePorts
$authProc = $authStart.process
$authListener = $authStart.listener
$authStdOut = $authStart.stdout
$authStdErr = $authStart.stderr

$worldStart = Start-GatewayWithRetry `
    -GatewayName "WorldGateway" `
    -DotnetHost $dotnetHost `
    -DllPath $worldDll `
    -WorkingDirectory $worldWorkDir `
    -Port $WorldPort `
    -TimeoutSeconds $StartupTimeoutSeconds `
    -RetryCount $StartupRetryCount `
    -RetryBackoffMs $StartupRetryBackoffMs `
    -RunlogsDirectory $runlogs `
    -ForceReleasePort $ForceReleasePorts
$worldProc = $worldStart.process
$worldListener = $worldStart.listener
$worldStdOut = $worldStart.stdout
$worldStdErr = $worldStart.stderr

$metadata = [ordered]@{
    started_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    hypothesis_id = $HypothesisId
    repo_root = $repoRoot
    authgateway_pid = $authProc.Id
    worldgateway_pid = $worldProc.Id
    dotnet_host = $dotnetHost
    auth_dll = $authDll
    world_dll = $worldDll
    auth_working_directory = $authWorkDir
    world_working_directory = $worldWorkDir
    auth_stdout = $authStdOut
    auth_stderr = $authStdErr
    world_stdout = $worldStdOut
    world_stderr = $worldStdErr
    auth_start_attempts_used = $authStart.attempts_used
    world_start_attempts_used = $worldStart.attempts_used
    startup_retry_count = $StartupRetryCount
    startup_retry_backoff_ms = $StartupRetryBackoffMs
    listeners_ready = $true
    listeners = @($worldListener, $authListener)
}

$metaPath = Join-Path $runlogs "retail_run.gateway_pids.json"
($metadata | ConvertTo-Json -Depth 6) | Set-Content -Path $metaPath -Encoding UTF8
Get-Content $metaPath -Raw
