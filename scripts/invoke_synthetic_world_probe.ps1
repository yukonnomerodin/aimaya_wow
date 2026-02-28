param(
    [string]$ServerHost = "127.0.0.1",
    [int]$Port = 8086,
    [int]$AccountId = 552,
    [int]$ConnectTimeoutMs = 4000,
    [int]$ReadTimeoutMs = 4000,
    [int]$MaxFramesBeforeAck = 12,
    [int]$PostAckWaitMs = 100,
    [switch]$SendCharEnumAfterAck,
    [switch]$EncryptCharEnumAfterAck,
    [string]$RunlogsPath = "docs/handshake/runlogs",
    [string]$RetailWorldEncryptKeyHex = "",
    [UInt64]$RetailWorldPacketCryptClientCounter = 0,
    [int]$CharEnumDelayMs = 250,
    [int]$PostAckReadFrames = 8,
    [int]$PostAckReadTimeoutMs = 250
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-Exact {
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [int]$Length
    )

    $buffer = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($buffer, $offset, $Length - $offset)
        if ($read -le 0) {
            throw "Socket closed while reading $Length bytes (offset=$offset)."
        }

        $offset += $read
    }

    return $buffer
}

function Read-RetailFrame {
    param([System.Net.Sockets.NetworkStream]$Stream)

    [byte[]]$header = Read-Exact -Stream $Stream -Length 16
    [uint32]$size = [BitConverter]::ToUInt32($header, 0)
    if ($size -lt 4) {
        throw "Invalid Retail frame size: $size"
    }

    [byte[]]$body = Read-Exact -Stream $Stream -Length ([int]$size)
    [uint32]$opcode = [BitConverter]::ToUInt32($body, 0)
    [int]$payloadLength = [int]$size - 4

    [byte[]]$payload = New-Object byte[] $payloadLength
    if ($payloadLength -gt 0) {
        [Array]::Copy($body, 4, $payload, 0, $payloadLength)
    }

    return [PSCustomObject]@{
        size = $size
        opcode = $opcode
        payload = $payload
    }
}

function Build-RetailFrame {
    param(
        [uint32]$Opcode,
        [byte[]]$Payload
    )

    [int]$payloadLength = if ($null -eq $Payload) { 0 } else { $Payload.Length }
    [uint32]$size = [uint32](4 + $payloadLength)
    [byte[]]$frame = New-Object byte[] (16 + $size)

    [Array]::Copy([BitConverter]::GetBytes($size), 0, $frame, 0, 4)
    [Array]::Copy([BitConverter]::GetBytes($Opcode), 0, $frame, 16, 4)
    if ($payloadLength -gt 0) {
        [Array]::Copy($Payload, 0, $frame, 20, $payloadLength)
    }

    return $frame
}

function Build-SyntheticAuthSessionPayload {
    param([int]$AccountId)

    [byte[]]$accountJson = [System.Text.Encoding]::ASCII.GetBytes("{`"accountId`":$AccountId}")
    [int]$total = 8 + 4 + 4 + 4 + 32 + 24 + $accountJson.Length
    [byte[]]$payload = New-Object byte[] $total

    [Array]::Copy([BitConverter]::GetBytes([uint32]1), 0, $payload, 8, 4)   # regionId
    [Array]::Copy([BitConverter]::GetBytes([uint32]1), 0, $payload, 12, 4)  # battlegroupId
    [Array]::Copy([BitConverter]::GetBytes([uint32]1), 0, $payload, 16, 4)  # realmId

    for ($idx = 0; $idx -lt 32; $idx++) {
        $payload[20 + $idx] = [byte](($idx * 17 + 7) -band 0xFF)
    }

    for ($idx = 0; $idx -lt 24; $idx++) {
        $payload[52 + $idx] = [byte](($idx * 11 + 3) -band 0xFF)
    }

    [Array]::Copy($accountJson, 0, $payload, 76, $accountJson.Length)
    return $payload
}

function Resolve-RepoPath {
    param([string]$PathValue)

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $PathValue))
}

function Get-LatestProofKeyHex {
    param(
        [string]$ResolvedRunlogsPath,
        [DateTimeOffset]$StartedAtUtc
    )

    if (-not (Test-Path $ResolvedRunlogsPath)) {
        throw "Runlogs path does not exist: $ResolvedRunlogsPath"
    }

    $proofFiles = Get-ChildItem -Path $ResolvedRunlogsPath -Filter "enter_encrypted_mode.sent.*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending

    foreach ($proofFile in $proofFiles) {
        if ($proofFile.LastWriteTimeUtc -lt $StartedAtUtc.UtcDateTime.AddSeconds(-2)) {
            continue
        }

        try {
            $metadata = Get-Content -Path $proofFile.FullName -Raw | ConvertFrom-Json
        }
        catch {
            continue
        }

        $keyHex = [string]$metadata.retail_world_encrypt_key_hex
        if ([string]::IsNullOrWhiteSpace($keyHex)) {
            continue
        }

        return [PSCustomObject]@{
            key_hex = $keyHex.Trim()
            source = $proofFile.FullName
        }
    }

    throw "Could not resolve retail_world_encrypt_key_hex from fresh enter_encrypted_mode proof in $ResolvedRunlogsPath."
}

function Convert-HexToBytes {
    param([string]$Hex)

    $normalized = if ($null -eq $Hex) { "" } else { $Hex.Trim() }
    if ($normalized.StartsWith("0x", [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring(2)
    }

    $normalized = [System.Text.RegularExpressions.Regex]::Replace($normalized, "\s+", "")
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw "Invalid hex value: empty."
    }

    if (($normalized.Length % 2) -ne 0) {
        throw "Invalid hex value length: $($normalized.Length)"
    }

    [byte[]]$bytes = New-Object byte[] ($normalized.Length / 2)
    for ($idx = 0; $idx -lt $bytes.Length; $idx++) {
        $pair = $normalized.Substring($idx * 2, 2)
        try {
            $bytes[$idx] = [Convert]::ToByte($pair, 16)
        }
        catch {
            throw "Invalid hex pair at index ${idx}: '$pair'"
        }
    }

    return $bytes
}

function Protect-RetailClientFrame {
    param(
        [byte[]]$PlainFrame,
        [byte[]]$Key32,
        [UInt64]$ClientCounter
    )

    if ($null -eq $PlainFrame -or $PlainFrame.Length -lt 20) {
        throw "Plain frame is too short for retail crypt."
    }

    if ($null -eq $Key32 -or $Key32.Length -ne 32) {
        throw "Retail world crypt key must be 32 bytes."
    }

    [uint32]$bodyLengthU32 = [BitConverter]::ToUInt32($PlainFrame, 0)
    if ($bodyLengthU32 -lt 4) {
        throw "Invalid retail frame body length: $bodyLengthU32"
    }

    [int]$frameBytes = 16 + [int]$bodyLengthU32
    if ($PlainFrame.Length -ne $frameBytes) {
        throw "Retail frame size mismatch: expected $frameBytes got $($PlainFrame.Length)"
    }

    [byte[]]$nonce = New-Object byte[] 12
    [byte[]]$counterBytes = [BitConverter]::GetBytes($ClientCounter)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($counterBytes)
    }

    [Array]::Copy($counterBytes, 0, $nonce, 0, 8)
    [byte[]]$magicBytes = [BitConverter]::GetBytes([uint32]0x544E4C43) # "CLNT"
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($magicBytes)
    }

    [Array]::Copy($magicBytes, 0, $nonce, 8, 4)

    [int]$bodyLength = [int]$bodyLengthU32
    [byte[]]$plainBody = New-Object byte[] $bodyLength
    [Array]::Copy($PlainFrame, 16, $plainBody, 0, $bodyLength)
    [byte[]]$ciphertext = New-Object byte[] $bodyLength
    [byte[]]$tag = New-Object byte[] 12

    $aes = [System.Security.Cryptography.AesGcm]::new($Key32, 12)
    try {
        $aes.Encrypt($nonce, $plainBody, $ciphertext, $tag)
    }
    finally {
        $aes.Dispose()
    }

    [byte[]]$encryptedFrame = New-Object byte[] $frameBytes
    [Array]::Copy($PlainFrame, 0, $encryptedFrame, 0, 4)
    [Array]::Copy($tag, 0, $encryptedFrame, 4, 12)
    [Array]::Copy($ciphertext, 0, $encryptedFrame, 16, $bodyLength)
    return $encryptedFrame
}

function Test-ByteArrayEquals {
    param(
        [byte[]]$Left,
        [byte[]]$Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return $false
    }

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    for ($idx = 0; $idx -lt $Left.Length; $idx++) {
        if ($Left[$idx] -ne $Right[$idx]) {
            return $false
        }
    }

    return $true
}

$serverInit = [System.Text.Encoding]::ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2`n")
$clientInit = [System.Text.Encoding]::ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2`n")

$client = New-Object System.Net.Sockets.TcpClient
$stream = $null
$observedOpcodes = New-Object System.Collections.Generic.List[string]
$postAckObservedOpcodes = New-Object System.Collections.Generic.List[string]
$enterEncryptedSeen = $false
$ackSent = $false
$authChallengeSeen = $false
$charEnumSent = $false
$charEnumEncrypted = $false
$charEnumEncryptionKeySource = ""
$charEnumResultSeen = $false
$probeStage = "startup"

$startedAt = [DateTimeOffset]::UtcNow
try {
    $probeStage = "connect"
    $asyncConnect = $client.BeginConnect($ServerHost, $Port, $null, $null)
    if (-not $asyncConnect.AsyncWaitHandle.WaitOne($ConnectTimeoutMs)) {
        throw "Connect timeout to ${ServerHost}:$Port after ${ConnectTimeoutMs}ms"
    }

    $client.EndConnect($asyncConnect)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $ReadTimeoutMs
    $stream.WriteTimeout = $ReadTimeoutMs

    $probeStage = "server_initializer"
    [byte[]]$serverHello = Read-Exact -Stream $stream -Length $serverInit.Length
    if (-not (Test-ByteArrayEquals -Left $serverHello -Right $serverInit)) {
        throw "Unexpected server initializer."
    }

    $stream.Write($clientInit, 0, $clientInit.Length)
    $stream.Flush()

    $probeStage = "await_auth_challenge"
    for ($scan = 0; $scan -lt 4; $scan++) {
        $frame = Read-RetailFrame -Stream $stream
        $observedOpcodes.Add(("0x{0:X8}" -f $frame.opcode))
        if ($frame.opcode -eq 0x00490000) {
            $authChallengeSeen = $true
            break
        }
    }

    if (-not $authChallengeSeen) {
        throw "SMSG_AUTH_CHALLENGE (0x00490000) not observed."
    }

    $probeStage = "send_auth_session"
    [byte[]]$authPayload = Build-SyntheticAuthSessionPayload -AccountId $AccountId
    [byte[]]$authFrame = Build-RetailFrame -Opcode 0x00410001 -Payload $authPayload
    $stream.Write($authFrame, 0, $authFrame.Length)
    $stream.Flush()

    $probeStage = "await_enter_encrypted"
    for ($idx = 0; $idx -lt $MaxFramesBeforeAck; $idx++) {
        $frame = Read-RetailFrame -Stream $stream
        $observedOpcodes.Add(("0x{0:X8}" -f $frame.opcode))
        if ($frame.opcode -eq 0x00490004) {
            $enterEncryptedSeen = $true
            break
        }
    }

    if (-not $enterEncryptedSeen) {
        throw "SMSG_ENTER_ENCRYPTED_MODE (0x00490004) not observed."
    }

    $probeStage = "send_ack"
    [byte[]]$ackFrame = Build-RetailFrame -Opcode 0x00410005 -Payload ([byte[]]::new(0))
    $stream.Write($ackFrame, 0, $ackFrame.Length)
    $stream.Flush()
    $ackSent = $true

    if ($SendCharEnumAfterAck) {
        $probeStage = "send_char_enum"
        if ($CharEnumDelayMs -gt 0) {
            Start-Sleep -Milliseconds $CharEnumDelayMs
        }

        [byte[]]$enumFrame = Build-RetailFrame -Opcode 0x00400014 -Payload ([byte[]]::new(0))
        [byte[]]$frameToSend = $enumFrame
        if ($EncryptCharEnumAfterAck) {
            $keyHex = $RetailWorldEncryptKeyHex
            $keySource = "parameter:RetailWorldEncryptKeyHex"
            if ([string]::IsNullOrWhiteSpace($keyHex)) {
                $resolvedRunlogsPath = Resolve-RepoPath -PathValue $RunlogsPath
                $proofKey = Get-LatestProofKeyHex -ResolvedRunlogsPath $resolvedRunlogsPath -StartedAtUtc $startedAt
                $keyHex = [string]$proofKey.key_hex
                $keySource = [string]$proofKey.source
            }

            [byte[]]$keyBytes = Convert-HexToBytes -Hex $keyHex
            if ($keyBytes.Length -ne 32) {
                throw "Retail world encrypt key length must be 32 bytes (got $($keyBytes.Length))."
            }

            $frameToSend = Protect-RetailClientFrame `
                -PlainFrame $enumFrame `
                -Key32 $keyBytes `
                -ClientCounter $RetailWorldPacketCryptClientCounter
            $charEnumEncrypted = $true
            $charEnumEncryptionKeySource = $keySource
        }

        $stream.Write($frameToSend, 0, $frameToSend.Length)
        $stream.Flush()
        $charEnumSent = $true
    }

    if ($PostAckReadFrames -gt 0 -and $PostAckReadTimeoutMs -gt 0) {
        $probeStage = "post_ack_read"
        $stream.ReadTimeout = $PostAckReadTimeoutMs
        for ($idx = 0; $idx -lt $PostAckReadFrames; $idx++) {
            try {
                $postAckFrame = Read-RetailFrame -Stream $stream
                $postOpcodeHex = ("0x{0:X8}" -f $postAckFrame.opcode)
                $postAckObservedOpcodes.Add($postOpcodeHex)
                if ($postAckFrame.opcode -eq 0x00420018) {
                    $charEnumResultSeen = $true
                }
            }
            catch {
                break
            }
        }

        $stream.ReadTimeout = $ReadTimeoutMs
    }

    $probeStage = "post_ack_wait"
    Start-Sleep -Milliseconds $PostAckWaitMs
    $probeStage = "completed"
}
catch {
    $message = [string]$_.Exception.Message
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = "unknown probe failure"
    }

    throw "[probe_stage=$probeStage] $message"
}
finally {
    if ($null -ne $stream) {
        $stream.Dispose()
    }

    if ($null -ne $client) {
        $client.Close()
        $client.Dispose()
    }
}

$finishedAt = [DateTimeOffset]::UtcNow

[PSCustomObject]@{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString("o")
    host = $ServerHost
    port = $Port
    account_id = $AccountId
    auth_challenge_seen = $authChallengeSeen
    enter_encrypted_seen = $enterEncryptedSeen
    ack_sent = $ackSent
    char_enum_sent = $charEnumSent
    encrypt_char_enum_after_ack = $EncryptCharEnumAfterAck.IsPresent
    char_enum_encrypted = $charEnumEncrypted
    char_enum_encryption_key_source = $charEnumEncryptionKeySource
    retail_world_packet_crypt_client_counter = $RetailWorldPacketCryptClientCounter
    char_enum_result_seen = $charEnumResultSeen
    observed_opcodes = $observedOpcodes
    post_ack_observed_opcodes = $postAckObservedOpcodes
    duration_ms = [Math]::Max(0, [int]($finishedAt - $startedAt).TotalMilliseconds)
} | ConvertTo-Json -Depth 6
