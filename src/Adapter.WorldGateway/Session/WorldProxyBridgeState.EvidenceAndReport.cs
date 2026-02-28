namespace Adapter.WorldGateway;

internal sealed partial class WorldProxyBridgeState
{
    public void SetConnectionOpenedAt(DateTimeOffset openedAt)
    {
        _connectionOpenedUnixMs = openedAt.ToUnixTimeMilliseconds();
        Volatile.Write(ref _hasConnectionOpenedUnixMs, 1);
    }

    public void MarkEnterEncryptedAwaitStart(string stagedOpcodes, int timeoutMs)
    {
        lock (_enterEncryptedSync)
        {
            _awaitingRetailOpcodes = stagedOpcodes;
            _awaitingTimeoutMs = timeoutMs;
        }
    }

    public void MarkEnterEncryptedAckObserved()
    {
        Volatile.Write(ref _ackObserved, 1);
    }

    public void MarkEnterEncryptedAckConfirmed(long elapsedMs)
    {
        _ackConfirmedElapsedMs = elapsedMs;
    }

    public void MarkEnterEncryptedAckTimeout(int pendingBytes, string pendingRetail)
    {
        lock (_enterEncryptedSync)
        {
            _ackTimeoutPendingBytes = pendingBytes;
            _ackTimeoutPendingRetail = pendingRetail;
        }
    }

    public void SetLogDisconnectReason(uint reason)
    {
        _logDisconnectReason = reason;
        if (Volatile.Read(ref _hasConnectionOpenedUnixMs) == 1)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            _logDisconnectElapsedMs = Math.Max(0, now - _connectionOpenedUnixMs);
        }
    }

    public void MarkClientRequestedDisconnect()
    {
        Volatile.Write(ref _clientRequestedDisconnect, 1);
    }

    public bool ConsumeClientRequestedDisconnect()
    {
        return Interlocked.Exchange(ref _clientRequestedDisconnect, 0) == 1;
    }

    public void SetProofPackArtifacts(string hexPath, string metadataPath, string diffPath)
    {
        lock (_enterEncryptedSync)
        {
            _proofHexPath = hexPath;
            _proofMetadataPath = metadataPath;
            _proofDiffPath = diffPath;
        }

        TryCaptureFirstDivergenceFromDiffPath(diffPath);
    }

    public bool AckObserved => Volatile.Read(ref _ackObserved) == 1;

    public bool TryGetAckConfirmedElapsedMs(out long elapsedMs)
    {
        elapsedMs = _ackConfirmedElapsedMs;
        return elapsedMs >= 0;
    }

    public bool TryGetDisconnect(out uint reason, out long elapsedMs)
    {
        reason = _logDisconnectReason;
        elapsedMs = _logDisconnectElapsedMs;
        return reason != uint.MaxValue;
    }

    public bool TryGetAckTimeout(out int pendingBytes, out string pendingRetail)
    {
        lock (_enterEncryptedSync)
        {
            if (_ackTimeoutPendingRetail is not null)
            {
                pendingBytes = _ackTimeoutPendingBytes;
                pendingRetail = _ackTimeoutPendingRetail;
                return true;
            }
        }

        pendingBytes = 0;
        pendingRetail = "<none>";
        return false;
    }

    public bool TryGetProofPackArtifacts(out string hexPath, out string metadataPath, out string diffPath)
    {
        lock (_enterEncryptedSync)
        {
            if (!string.IsNullOrWhiteSpace(_proofHexPath) &&
                !string.IsNullOrWhiteSpace(_proofMetadataPath) &&
                !string.IsNullOrWhiteSpace(_proofDiffPath))
            {
                hexPath = _proofHexPath;
                metadataPath = _proofMetadataPath;
                diffPath = _proofDiffPath;
                return true;
            }
        }

        hexPath = string.Empty;
        metadataPath = string.Empty;
        diffPath = string.Empty;
        return false;
    }

    public string AwaitingRetailOpcodes
    {
        get
        {
            lock (_enterEncryptedSync)
            {
                return _awaitingRetailOpcodes ?? "<none>";
            }
        }
    }

    public int AwaitingTimeoutMs
    {
        get
        {
            lock (_enterEncryptedSync)
            {
                return _awaitingTimeoutMs;
            }
        }
    }
}
