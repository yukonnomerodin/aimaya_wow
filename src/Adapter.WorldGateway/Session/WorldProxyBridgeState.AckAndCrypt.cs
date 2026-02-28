using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

internal sealed partial class WorldProxyBridgeState
{
    public bool IsAwaitingEnterEncryptedAck => Volatile.Read(ref _isAwaitingEnterEncryptedAck) == 1;

    public void SetAcoreAuthSeed(uint seed)
    {
        _acoreAuthSeed = seed;
        Volatile.Write(ref _hasAcoreAuthSeed, 1);
    }

    public bool TryGetAcoreAuthSeed(out uint seed)
    {
        if (Volatile.Read(ref _hasAcoreAuthSeed) == 1)
        {
            seed = _acoreAuthSeed;
            return true;
        }

        seed = 0;
        return false;
    }

    public void SetAcoreServerChallenge(ReadOnlySpan<byte> challenge)
    {
        if (challenge.Length != 32)
        {
            return;
        }

        byte[] copy = GC.AllocateUninitializedArray<byte>(32);
        challenge.CopyTo(copy);
        _acoreServerChallenge = copy;
        Volatile.Write(ref _hasAcoreServerChallenge, 1);
    }

    public bool TryGetAcoreServerChallenge(out byte[] challenge)
    {
        if (Volatile.Read(ref _hasAcoreServerChallenge) == 1 && _acoreServerChallenge is not null)
        {
            challenge = _acoreServerChallenge;
            return true;
        }

        challenge = Array.Empty<byte>();
        return false;
    }

    public bool TrySetAcoreHeaderCrypt(AuthCrypt authCrypt)
    {
        ArgumentNullException.ThrowIfNull(authCrypt);
        if (!authCrypt.IsInitialized)
        {
            return false;
        }

        if (Interlocked.CompareExchange(ref _hasAcoreHeaderCrypt, 1, 0) == 0)
        {
            _acoreHeaderCrypt = authCrypt;
            return true;
        }

        return false;
    }

    public bool TryGetAcoreHeaderCrypt(out AuthCrypt authCrypt)
    {
        if (Volatile.Read(ref _hasAcoreHeaderCrypt) == 1 && _acoreHeaderCrypt is not null)
        {
            authCrypt = _acoreHeaderCrypt;
            return true;
        }

        authCrypt = null!;
        return false;
    }

    public bool TrySetRetailEnterEncryptedModeFrame(byte[] frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Length == 0)
        {
            return false;
        }

        if (Interlocked.CompareExchange(ref _hasRetailEnterEncryptedModeFrame, 1, 0) == 0)
        {
            _retailEnterEncryptedModeFrame = frame;
            return true;
        }

        return false;
    }

    public bool TryGetRetailEnterEncryptedModeFrame(out byte[] frame)
    {
        if (Volatile.Read(ref _hasRetailEnterEncryptedModeFrame) == 1 && _retailEnterEncryptedModeFrame is not null)
        {
            frame = _retailEnterEncryptedModeFrame;
            return true;
        }

        frame = Array.Empty<byte>();
        return false;
    }

    public bool TrySetRetailWorldEncryptKey(byte[] key32)
    {
        ArgumentNullException.ThrowIfNull(key32);
        if (key32.Length != 32)
        {
            return false;
        }

        byte[] copy = GC.AllocateUninitializedArray<byte>(32);
        key32.AsSpan().CopyTo(copy);

        lock (_retailWorldCryptSync)
        {
            _retailWorldEncryptKey = copy;
            Volatile.Write(ref _hasRetailWorldEncryptKey, 1);
        }

        return true;
    }

    public bool TryEnableRetailWorldCrypt(out string? error)
    {
        error = null;

        if (Volatile.Read(ref _isRetailWorldCryptActive) == 1)
        {
            return true;
        }

        lock (_retailWorldCryptSync)
        {
            if (Volatile.Read(ref _isRetailWorldCryptActive) == 1)
            {
                return true;
            }

            if (Volatile.Read(ref _hasRetailWorldEncryptKey) != 1 ||
                _retailWorldEncryptKey is null ||
                _retailWorldEncryptKey.Length != 32)
            {
                error = "Retail world encrypt key is missing.";
                return false;
            }

            try
            {
                _retailWorldCrypt.Init(_retailWorldEncryptKey);
                Volatile.Write(ref _isRetailWorldCryptActive, 1);
                return true;
            }
            catch (CryptographicException ex)
            {
                error = ex.Message;
                return false;
            }
            catch (ArgumentException ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }

    public bool IsRetailWorldCryptActive => Volatile.Read(ref _isRetailWorldCryptActive) == 1;

    public bool TryProtectRetailServerFrame(
        byte[] plainFrame,
        out byte[] protectedFrame,
        out ulong serverCounterUsed,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(plainFrame);

        bool cryptInitialized;
        lock (_retailWorldCryptSync)
        {
            if (!_retailWorldCrypt.TryProtectServerFrame(plainFrame, out protectedFrame, out serverCounterUsed, out error))
            {
                return false;
            }

            cryptInitialized = _retailWorldCrypt.IsInitialized;
        }

        bool ackObserved = Volatile.Read(ref _ackObserved) == 1;
        if (!ackObserved)
        {
            int preAckIndex = Interlocked.Increment(ref _preAckProtectedFramesSeen);
            if (preAckIndex <= PreAckTraceMaxFrames)
            {
                ulong ctrAfter = unchecked(serverCounterUsed + 1UL);
                bool awaitingAck = Volatile.Read(ref _isAwaitingEnterEncryptedAck) == 1;
                bool worldCryptActive = Volatile.Read(ref _isRetailWorldCryptActive) == 1;

                if (plainFrame.Length < 20)
                {
                    _logger.LogInformation(
                        "[OURS][PRE_ACK][#{Index}] malformed_plain_frame_bytes={PlainFrameBytes} ctr_before={CtrBefore} ctr_after={CtrAfter} frame_size={FrameSize} awaiting_ack={AwaitingAck} world_crypt_active={WorldCryptActive} crypt_initialized={CryptInitialized}",
                        preAckIndex,
                        plainFrame.Length,
                        serverCounterUsed,
                        ctrAfter,
                        protectedFrame.Length,
                        awaitingAck,
                        worldCryptActive,
                        cryptInitialized);
                }
                else
                {
                    uint plainLen = BinaryPrimitives.ReadUInt32LittleEndian(plainFrame.AsSpan(0, 4));
                    uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(plainFrame.AsSpan(16, 4));
                    uint payloadLen = plainLen >= 4 ? plainLen - 4 : 0;
                    int payloadHeadLen = (int)Math.Min((uint)PostAckTraceHeadBytes, payloadLen);
                    int availablePayloadHead = Math.Max(0, plainFrame.Length - 20);
                    payloadHeadLen = Math.Min(payloadHeadLen, availablePayloadHead);
                    string plainHead = payloadHeadLen > 0
                        ? Convert.ToHexString(plainFrame.AsSpan(20, payloadHeadLen))
                        : string.Empty;

                    _logger.LogInformation(
                        "[OURS][PRE_ACK][#{Index}] opcode=0x{Opcode:X8} plain_len={PlainLen} payload_len={PayloadLen} plain_head={PlainHead} ctr_before={CtrBefore} ctr_after={CtrAfter} frame_size={FrameSize} awaiting_ack={AwaitingAck} world_crypt_active={WorldCryptActive} crypt_initialized={CryptInitialized}",
                        preAckIndex,
                        opcode,
                        plainLen,
                        payloadLen,
                        plainHead,
                        serverCounterUsed,
                        ctrAfter,
                        protectedFrame.Length,
                        awaitingAck,
                        worldCryptActive,
                        cryptInitialized);
                }
            }
        }

        if (ackObserved)
        {
            int postAckIndex = Interlocked.Increment(ref _postAckProtectedFramesSeen);
            if (postAckIndex <= PostAckTraceMaxFrames)
            {
                ulong ctrAfter = unchecked(serverCounterUsed + 1UL);
                if (plainFrame.Length < 20)
                {
                    _logger.LogInformation(
                        "[OURS][POST_ACK][#{Index}] malformed_plain_frame_bytes={PlainFrameBytes} ctr_before={CtrBefore} ctr_after={CtrAfter} frame_size={FrameSize}",
                        postAckIndex,
                        plainFrame.Length,
                        serverCounterUsed,
                        ctrAfter,
                        protectedFrame.Length);
                }
                else
                {
                    uint plainLen = BinaryPrimitives.ReadUInt32LittleEndian(plainFrame.AsSpan(0, 4));
                    uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(plainFrame.AsSpan(16, 4));
                    uint payloadLen = plainLen >= 4 ? plainLen - 4 : 0;
                    int availableBodyBytes = Math.Max(0, plainFrame.Length - 16);
                    int bodyHashBytes = Math.Min((int)plainLen, availableBodyBytes);
                    int payloadHashBytes = Math.Max(0, bodyHashBytes - 4);
                    int payloadHeadLen = (int)Math.Min((uint)PostAckTraceHeadBytes, payloadLen);
                    int availablePayloadHead = Math.Max(0, plainFrame.Length - 20);
                    payloadHeadLen = Math.Min(payloadHeadLen, availablePayloadHead);
                    string plainHead = payloadHeadLen > 0
                        ? Convert.ToHexString(plainFrame.AsSpan(20, payloadHeadLen))
                        : string.Empty;
                    string bodySha256 = Convert.ToHexString(SHA256.HashData(plainFrame.AsSpan(16, bodyHashBytes)));
                    string payloadSha256 = Convert.ToHexString(SHA256.HashData(plainFrame.AsSpan(20, payloadHashBytes)));
                    string frameSha256 = Convert.ToHexString(SHA256.HashData(plainFrame));

                    _logger.LogInformation(
                        "[OURS][POST_ACK][#{Index}] opcode=0x{Opcode:X8} plain_len={PlainLen} payload_len={PayloadLen} plain_head={PlainHead} body_sha256={BodySha256} payload_sha256={PayloadSha256} frame_sha256={FrameSha256} ctr_before={CtrBefore} ctr_after={CtrAfter} frame_size={FrameSize}",
                        postAckIndex,
                        opcode,
                        plainLen,
                        payloadLen,
                        plainHead,
                        bodySha256,
                        payloadSha256,
                        frameSha256,
                        serverCounterUsed,
                        ctrAfter,
                        protectedFrame.Length);

                    if (postAckIndex == 1)
                    {
                        string bodyHex = bodyHashBytes > 0
                            ? Convert.ToHexString(plainFrame.AsSpan(16, bodyHashBytes))
                            : string.Empty;
                        string payloadHex = payloadHashBytes > 0
                            ? Convert.ToHexString(plainFrame.AsSpan(20, payloadHashBytes))
                            : string.Empty;

                        _logger.LogInformation(
                            "[OURS][POST_ACK][#1][FULL] body_hex={BodyHex} payload_hex={PayloadHex}",
                            bodyHex,
                            payloadHex);
                    }
                }
            }
        }

        return true;
    }

    public bool TryDecryptRetailClientFrame(ReadOnlySpan<byte> encryptedFrame, out byte[] plainFrame, out string? error)
    {
        lock (_retailWorldCryptSync)
        {
            return _retailWorldCrypt.TryDecodeClientFrame(encryptedFrame, out plainFrame, out error);
        }
    }

    public void BeginEnterEncryptedAwait()
    {
        lock (_enterEncryptedSync)
        {
            _enterEncryptedAckEvent.Reset();
            Volatile.Write(ref _isAwaitingEnterEncryptedAck, 1);
        }
    }

    public bool SignalEnterEncryptedAck()
    {
        lock (_enterEncryptedSync)
        {
            if (Volatile.Read(ref _isAwaitingEnterEncryptedAck) != 1)
            {
                return false;
            }

            _enterEncryptedAckEvent.Set();
            return true;
        }
    }

    public bool WaitForEnterEncryptedAck(TimeSpan timeout)
    {
        if (Volatile.Read(ref _isAwaitingEnterEncryptedAck) != 1)
        {
            return true;
        }

        return _enterEncryptedAckEvent.Wait(timeout);
    }

    public void ResetEnterEncryptedAwait()
    {
        lock (_enterEncryptedSync)
        {
            Volatile.Write(ref _isAwaitingEnterEncryptedAck, 0);
            _enterEncryptedAckEvent.Reset();
        }
    }

    public bool RegisterPostAckNonAckBootstrapTrigger(uint opcode)
    {
        lock (_enterEncryptedSync)
        {
            if (Volatile.Read(ref _ackObserved) != 1)
            {
                return false;
            }

            if (_postAckNonAckBootstrapTriggerOpcode != uint.MaxValue)
            {
                return false;
            }

            _postAckNonAckBootstrapTriggerOpcode = opcode;
            _postAckNonAckBootstrapTriggerEvent.Set();
            return true;
        }
    }

    public void BeginPostAckNonAckBootstrapTriggerAwait()
    {
        lock (_enterEncryptedSync)
        {
            Volatile.Write(ref _isAwaitingPostAckNonAckBootstrapTrigger, 1);
            if (_postAckNonAckBootstrapTriggerOpcode == uint.MaxValue)
            {
                _postAckNonAckBootstrapTriggerEvent.Reset();
            }
            else
            {
                _postAckNonAckBootstrapTriggerEvent.Set();
            }
        }
    }

    public bool WaitForPostAckNonAckBootstrapTrigger(TimeSpan timeout)
    {
        if (_postAckNonAckBootstrapTriggerOpcode != uint.MaxValue)
        {
            return true;
        }

        if (Volatile.Read(ref _isAwaitingPostAckNonAckBootstrapTrigger) != 1)
        {
            return false;
        }

        return _postAckNonAckBootstrapTriggerEvent.Wait(timeout);
    }

    public void EndPostAckNonAckBootstrapTriggerAwait()
    {
        lock (_enterEncryptedSync)
        {
            Volatile.Write(ref _isAwaitingPostAckNonAckBootstrapTrigger, 0);
        }
    }

    public bool TryGetPostAckNonAckBootstrapTriggerOpcode(out uint opcode)
    {
        lock (_enterEncryptedSync)
        {
            if (_postAckNonAckBootstrapTriggerOpcode != uint.MaxValue)
            {
                opcode = _postAckNonAckBootstrapTriggerOpcode;
                return true;
            }
        }

        opcode = 0;
        return false;
    }

    public void MarkPostAckNonAckBootstrapTriggerWait(long waitMs)
    {
        lock (_enterEncryptedSync)
        {
            _postAckNonAckBootstrapTriggerWaitMs = Math.Max(0, waitMs);
        }
    }

    public bool TryGetPostAckNonAckBootstrapTriggerWait(out long waitMs)
    {
        lock (_enterEncryptedSync)
        {
            waitMs = _postAckNonAckBootstrapTriggerWaitMs;
            return waitMs >= 0;
        }
    }

    public void MarkDeferredFlushPath(string flushPath)
    {
        lock (_enterEncryptedSync)
        {
            _deferredFlushPath = string.IsNullOrWhiteSpace(flushPath) ? "<none>" : flushPath;
        }
    }

    public string DeferredFlushPath
    {
        get
        {
            lock (_enterEncryptedSync)
            {
                return _deferredFlushPath;
            }
        }
    }

}
