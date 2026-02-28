namespace Adapter.WorldGateway;

internal sealed partial class WorldProxyBridgeState
{
    public void EnqueuePendingDbQueryBulkReplies(uint tableHash, int[] recordIds)
    {
        ArgumentNullException.ThrowIfNull(recordIds);

        int[] copy = GC.AllocateUninitializedArray<int>(recordIds.Length);
        recordIds.AsSpan().CopyTo(copy);

        lock (_enterEncryptedSync)
        {
            _pendingDbQueryBulkReplies.Enqueue(new PendingDbQueryBulkReplies(tableHash, copy));
        }
    }

    public bool TryDequeuePendingDbQueryBulkReplies(out uint tableHash, out int[] recordIds)
    {
        lock (_enterEncryptedSync)
        {
            if (_pendingDbQueryBulkReplies.Count > 0)
            {
                PendingDbQueryBulkReplies next = _pendingDbQueryBulkReplies.Dequeue();
                tableHash = next.TableHash;
                recordIds = next.RecordIds;
                return true;
            }
        }

        tableHash = 0;
        recordIds = Array.Empty<int>();
        return false;
    }

    public void EnqueuePendingBattleNetResponse(ulong methodType, ulong objectId, uint token)
    {
        lock (_enterEncryptedSync)
        {
            _pendingBattleNetResponses.Enqueue(new PendingBattleNetResponse(methodType, objectId, token));
        }
    }

    public bool TryDequeuePendingBattleNetResponse(out ulong methodType, out ulong objectId, out uint token)
    {
        lock (_enterEncryptedSync)
        {
            if (_pendingBattleNetResponses.Count > 0)
            {
                PendingBattleNetResponse next = _pendingBattleNetResponses.Dequeue();
                methodType = next.MethodType;
                objectId = next.ObjectId;
                token = next.Token;
                return true;
            }
        }

        methodType = 0;
        objectId = 0;
        token = 0;
        return false;
    }

    public void MarkPendingSocialContractRequest()
    {
        lock (_enterEncryptedSync)
        {
            _pendingSocialContractRequest = true;
        }
    }

    public bool ConsumePendingSocialContractRequest()
    {
        lock (_enterEncryptedSync)
        {
            bool pending = _pendingSocialContractRequest;
            _pendingSocialContractRequest = false;
            return pending;
        }
    }

    public void MarkPendingUndeleteCooldownStatusRequest()
    {
        lock (_enterEncryptedSync)
        {
            _pendingUndeleteCooldownStatusRequest = true;
        }
    }

    public bool ConsumePendingUndeleteCooldownStatusRequest()
    {
        lock (_enterEncryptedSync)
        {
            bool pending = _pendingUndeleteCooldownStatusRequest;
            _pendingUndeleteCooldownStatusRequest = false;
            return pending;
        }
    }

    public void MarkPendingHotfixRequest()
    {
        lock (_enterEncryptedSync)
        {
            _pendingHotfixRequest = true;
        }
    }

    public bool ConsumePendingHotfixRequest()
    {
        lock (_enterEncryptedSync)
        {
            bool pending = _pendingHotfixRequest;
            _pendingHotfixRequest = false;
            return pending;
        }
    }

    public void MarkPendingServerTimeOffsetRequest()
    {
        lock (_enterEncryptedSync)
        {
            _pendingServerTimeOffsetRequest = true;
        }
    }

    public bool ConsumePendingServerTimeOffsetRequest()
    {
        lock (_enterEncryptedSync)
        {
            bool pending = _pendingServerTimeOffsetRequest;
            _pendingServerTimeOffsetRequest = false;
            return pending;
        }
    }

    public bool TryArmPendingGlueKick()
    {
        lock (_enterEncryptedSync)
        {
            if (_pendingGlueKick)
            {
                return false;
            }

            _pendingGlueKick = true;
            return true;
        }
    }

    public bool ConsumePendingGlueKick()
    {
        lock (_enterEncryptedSync)
        {
            bool pending = _pendingGlueKick;
            _pendingGlueKick = false;
            return pending;
        }
    }

    public void ClearPendingGlueKick()
    {
        lock (_enterEncryptedSync)
        {
            _pendingGlueKick = false;
        }
    }

    public void QueueDeferredPostAuthPayload(byte[] payload, string stagedOpcodes)
    {
        ArgumentNullException.ThrowIfNull(payload);
        lock (_enterEncryptedSync)
        {
            _deferredPostAuthPayload = payload;
            _deferredPostAuthOpcodes = stagedOpcodes;
        }
    }

    public bool TryTakeDeferredPostAuthPayload(out byte[] payload, out string stagedOpcodes)
    {
        lock (_enterEncryptedSync)
        {
            if (_deferredPostAuthPayload is { Length: > 0 } queuedPayload)
            {
                payload = queuedPayload;
                stagedOpcodes = _deferredPostAuthOpcodes ?? "<unknown>";
                _deferredPostAuthPayload = null;
                _deferredPostAuthOpcodes = null;
                return true;
            }
        }

        payload = Array.Empty<byte>();
        stagedOpcodes = string.Empty;
        return false;
    }

    public bool TryPeekDeferredPostAuthInfo(out int payloadBytes, out string stagedOpcodes)
    {
        lock (_enterEncryptedSync)
        {
            if (_deferredPostAuthPayload is { Length: > 0 } queuedPayload)
            {
                payloadBytes = queuedPayload.Length;
                stagedOpcodes = _deferredPostAuthOpcodes ?? "<unknown>";
                return true;
            }
        }

        payloadBytes = 0;
        stagedOpcodes = "<none>";
        return false;
    }

    public void BeginDeferredBootstrapFlush(int totalFrames)
    {
        lock (_enterEncryptedSync)
        {
            _deferredFramesTotal = Math.Max(0, totalFrames);
            _deferredFramesSent = 0;
            _deferredFirstOpcode = uint.MaxValue;
            _deferredFirstBodyLength = -1;
            _deferredFirstFrameBytes = -1;
            _deferredFirstServerCounter = ulong.MaxValue;
            _deferredFirstPlainSha256 = null;
            _deferredFirstProtectedSha256 = null;
            _deferredFirstProtectedTagHex = null;
            _deferredFirstParityStatus = null;
            _deferredFirstParityDiffOffset = -1;
            _deferredFirstParityExpectedBytes = null;
            _deferredFirstParityActualBytes = null;
            _deferredFirstParityFixturePath = null;
        }
    }

    public void MarkDeferredFrameSent(
        int index,
        int total,
        uint opcode,
        int bodyLength,
        int frameBytes,
        ulong serverCounterUsed,
        string plainSha256,
        string protectedSha256,
        string protectedTagHex,
        DeferredFrameParityResult parity)
    {
        lock (_enterEncryptedSync)
        {
            _deferredFramesTotal = Math.Max(_deferredFramesTotal, Math.Max(0, total));
            _deferredFramesSent = Math.Max(_deferredFramesSent, Math.Max(0, index));
            if (_deferredFirstOpcode == uint.MaxValue)
            {
                _deferredFirstOpcode = opcode;
                _deferredFirstBodyLength = bodyLength;
                _deferredFirstFrameBytes = frameBytes;
                _deferredFirstServerCounter = serverCounterUsed;
                _deferredFirstPlainSha256 = plainSha256;
                _deferredFirstProtectedSha256 = protectedSha256;
                _deferredFirstProtectedTagHex = protectedTagHex;
                _deferredFirstParityStatus = parity.Status;
                _deferredFirstParityDiffOffset = parity.DiffOffset ?? -1;
                _deferredFirstParityExpectedBytes = parity.ExpectedBytes;
                _deferredFirstParityActualBytes = parity.ActualBytes;
                _deferredFirstParityFixturePath = parity.FixturePath;
            }
        }
    }

    public bool TryGetDeferredFrameBoundary(out int sent, out int total)
    {
        lock (_enterEncryptedSync)
        {
            total = _deferredFramesTotal;
            sent = _deferredFramesSent;
            return total > 0;
        }
    }

    public bool TryGetFirstDeferredFrame(out uint opcode, out int bodyLength, out int frameBytes)
    {
        lock (_enterEncryptedSync)
        {
            if (_deferredFirstOpcode != uint.MaxValue)
            {
                opcode = _deferredFirstOpcode;
                bodyLength = _deferredFirstBodyLength;
                frameBytes = _deferredFirstFrameBytes;
                return true;
            }
        }

        opcode = 0;
        bodyLength = 0;
        frameBytes = 0;
        return false;
    }

    public bool TryGetFirstDeferredFrameEvidence(
        out ulong serverCounterUsed,
        out string plainSha256,
        out string protectedSha256,
        out string protectedTagHex)
    {
        lock (_enterEncryptedSync)
        {
            if (_deferredFirstOpcode != uint.MaxValue &&
                !string.IsNullOrWhiteSpace(_deferredFirstPlainSha256) &&
                !string.IsNullOrWhiteSpace(_deferredFirstProtectedSha256) &&
                !string.IsNullOrWhiteSpace(_deferredFirstProtectedTagHex))
            {
                serverCounterUsed = _deferredFirstServerCounter;
                plainSha256 = _deferredFirstPlainSha256;
                protectedSha256 = _deferredFirstProtectedSha256;
                protectedTagHex = _deferredFirstProtectedTagHex;
                return true;
            }
        }

        serverCounterUsed = 0;
        plainSha256 = string.Empty;
        protectedSha256 = string.Empty;
        protectedTagHex = string.Empty;
        return false;
    }

    public bool TryGetFirstDeferredFrameParity(
        out string status,
        out int? diffOffset,
        out string? expectedBytes,
        out string? actualBytes,
        out string? fixturePath)
    {
        lock (_enterEncryptedSync)
        {
            if (!string.IsNullOrWhiteSpace(_deferredFirstParityStatus))
            {
                status = _deferredFirstParityStatus;
                diffOffset = _deferredFirstParityDiffOffset >= 0 ? _deferredFirstParityDiffOffset : null;
                expectedBytes = _deferredFirstParityExpectedBytes;
                actualBytes = _deferredFirstParityActualBytes;
                fixturePath = _deferredFirstParityFixturePath;
                return true;
            }
        }

        status = "not_evaluated";
        diffOffset = null;
        expectedBytes = null;
        actualBytes = null;
        fixturePath = null;
        return false;
    }

    private readonly record struct PendingDbQueryBulkReplies(uint TableHash, int[] RecordIds);
    private readonly record struct PendingBattleNetResponse(ulong MethodType, ulong ObjectId, uint Token);
}
