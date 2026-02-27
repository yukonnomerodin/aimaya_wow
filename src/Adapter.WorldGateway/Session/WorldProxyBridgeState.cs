using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

internal sealed class WorldProxyBridgeState
{
    private const uint ClientOpcodeEnterEncryptedModeAck = WorldGatewayOpcodes.RetailCmsgEnterEncryptedModeAck;
    private const uint ClientOpcodeEnumCharacters = WorldGatewayOpcodes.RetailCmsgEnumCharacters;
    private const ushort ServerOpcodeAuthResponse = WorldGatewayOpcodes.AcoreSmsgAuthResponse;
    private const ushort ServerOpcodeCharEnum = WorldGatewayOpcodes.AcoreSmsgCharEnum;
    private const int PreAckTraceMaxFrames = 6;
    private const int PostAckTraceMaxFrames = 9;
    private const int PostAckTraceHeadBytes = 64;

    private readonly ILogger<WorldProxyListener> _logger;
    private readonly object _stageSync = new();
    private uint _acoreAuthSeed;
    private int _hasAcoreAuthSeed;
    private AuthCrypt? _acoreHeaderCrypt;
    private int _hasAcoreHeaderCrypt;
    private byte[]? _acoreServerChallenge;
    private int _hasAcoreServerChallenge;
    private byte[]? _retailEnterEncryptedModeFrame;
    private int _hasRetailEnterEncryptedModeFrame;
    private readonly object _enterEncryptedSync = new();
    private readonly object _retailWorldCryptSync = new();
    private readonly ManualResetEventSlim _enterEncryptedAckEvent = new(initialState: false);
    private readonly ManualResetEventSlim _postAckNonAckBootstrapTriggerEvent = new(initialState: false);
    private readonly ulong _retailWorldPacketCryptServerInitialCounter;
    private readonly bool _retailWorldPacketCryptUseSizeAsAad;
    private readonly int _retailWorldPacketCryptAadSizeBytes;
    private readonly bool _retailWorldPacketCryptUseEmptyAad;
    private readonly string _retailWorldPacketCryptNonceLayout;
    private readonly string _retailWorldPacketCryptServerNonceMagic;
    private readonly string _retailWorldPacketCryptClientNonceMagic;
    private int _isAwaitingEnterEncryptedAck;
    private int _isAwaitingPostAckNonAckBootstrapTrigger;
    private uint _postAckNonAckBootstrapTriggerOpcode = uint.MaxValue;
    private byte[]? _retailWorldEncryptKey;
    private int _hasRetailWorldEncryptKey;
    private readonly TrinityWorldPacketCrypt _retailWorldCrypt;
    private int _isRetailWorldCryptActive;
    private byte[]? _deferredPostAuthPayload;
    private string? _deferredPostAuthOpcodes;
    private long _connectionOpenedUnixMs;
    private int _hasConnectionOpenedUnixMs;
    private int _ackObserved;
    private long _ackConfirmedElapsedMs = -1;
    private uint _logDisconnectReason = uint.MaxValue;
    private long _logDisconnectElapsedMs = -1;
    private int _ackTimeoutPendingBytes;
    private string? _ackTimeoutPendingRetail;
    private string? _proofHexPath;
    private string? _proofMetadataPath;
    private string? _proofDiffPath;
    private string? _awaitingRetailOpcodes;
    private int _awaitingTimeoutMs;
    private BridgeStage _currentStage = BridgeStage.PRE_AUTH;
    private readonly List<StageTransitionEvent> _stageTransitions = new();
    private readonly List<TemporalInvariantResult> _temporalInvariants = new();
    private HandshakeBaseline? _baseline;
    private string? _failureClassTarget;
    private string? _activeLayer;
    private string? _parityAxis;
    private FirstDivergenceRecord? _firstDivergence;
    private int _deferredFramesTotal;
    private int _deferredFramesSent;
    private uint _deferredFirstOpcode = uint.MaxValue;
    private int _deferredFirstBodyLength = -1;
    private int _deferredFirstFrameBytes = -1;
    private ulong _deferredFirstServerCounter = ulong.MaxValue;
    private string? _deferredFirstPlainSha256;
    private string? _deferredFirstProtectedSha256;
    private string? _deferredFirstProtectedTagHex;
    private string? _deferredFirstParityStatus;
    private int _deferredFirstParityDiffOffset = -1;
    private string? _deferredFirstParityExpectedBytes;
    private string? _deferredFirstParityActualBytes;
    private string? _deferredFirstParityFixturePath;
    private string _deferredFlushPath = "<none>";
    private long _postAckNonAckBootstrapTriggerWaitMs = -1;
    private int _preAckProtectedFramesSeen;
    private int _postAckProtectedFramesSeen;
    private readonly Queue<PendingDbQueryBulkReplies> _pendingDbQueryBulkReplies = new();
    private readonly Queue<PendingBattleNetResponse> _pendingBattleNetResponses = new();
    private bool _pendingSocialContractRequest;
    private bool _pendingUndeleteCooldownStatusRequest;
    private bool _pendingHotfixRequest;
    private bool _pendingServerTimeOffsetRequest;
    private bool _pendingGlueKick;
    private int _clientRequestedDisconnect;

    public WorldProxyBridgeState(
        ILogger<WorldProxyListener> logger,
        ulong retailWorldPacketCryptServerInitialCounter = 0,
        bool retailWorldPacketCryptUseSizeAsAad = false,
        int retailWorldPacketCryptAadSizeBytes = 4,
        bool retailWorldPacketCryptUseEmptyAad = false,
        string retailWorldPacketCryptNonceLayout = "counter_le_magic_le",
        string retailWorldPacketCryptServerNonceMagic = "srvr",
        string retailWorldPacketCryptClientNonceMagic = "clnt")
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _retailWorldPacketCryptServerInitialCounter = retailWorldPacketCryptServerInitialCounter;
        _retailWorldPacketCryptUseSizeAsAad = retailWorldPacketCryptUseSizeAsAad;
        _retailWorldPacketCryptAadSizeBytes = retailWorldPacketCryptAadSizeBytes;
        _retailWorldPacketCryptUseEmptyAad = retailWorldPacketCryptUseEmptyAad;
        _retailWorldPacketCryptNonceLayout = retailWorldPacketCryptNonceLayout;
        _retailWorldPacketCryptServerNonceMagic = retailWorldPacketCryptServerNonceMagic;
        _retailWorldPacketCryptClientNonceMagic = retailWorldPacketCryptClientNonceMagic;
        _retailWorldCrypt = new TrinityWorldPacketCrypt(
            serverInitialCounter: _retailWorldPacketCryptServerInitialCounter,
            useSizeAsAad: _retailWorldPacketCryptUseSizeAsAad,
            aadSizeBytes: _retailWorldPacketCryptAadSizeBytes,
            useEmptyAad: _retailWorldPacketCryptUseEmptyAad,
            nonceLayout: _retailWorldPacketCryptNonceLayout,
            serverNonceMagic: _retailWorldPacketCryptServerNonceMagic,
            clientNonceMagic: _retailWorldPacketCryptClientNonceMagic);
        string timestamp = DateTimeOffset.UtcNow.ToString("O");
        _stageTransitions.Add(new StageTransitionEvent(timestamp, BridgeStage.PRE_AUTH, BridgeStage.PRE_AUTH, "state_initialized"));
    }

    public BridgeStage CurrentStage
    {
        get
        {
            lock (_stageSync)
            {
                return _currentStage;
            }
        }
    }

    public void SetBaseline(HandshakeBaseline baseline)
    {
        lock (_stageSync)
        {
            _baseline = baseline;
            _failureClassTarget = baseline.FailureClassTarget;
            _activeLayer = baseline.ActiveLayer;
            _parityAxis = baseline.ParityAxis;
        }
    }

    public void SetEvidenceContext(string layer, string parityAxis)
    {
        lock (_stageSync)
        {
            if (!string.IsNullOrWhiteSpace(layer))
            {
                _activeLayer = layer;
            }

            if (!string.IsNullOrWhiteSpace(parityAxis))
            {
                _parityAxis = parityAxis;
            }
        }
    }

    public bool TryGetBaseline(out HandshakeBaseline baseline)
    {
        lock (_stageSync)
        {
            if (_baseline is not null)
            {
                baseline = _baseline.Value;
                return true;
            }
        }

        baseline = default;
        return false;
    }

    public bool TryTransitionStage(BridgeStage nextStage, string reason)
    {
        lock (_stageSync)
        {
            BridgeStage current = _currentStage;
            if (nextStage == current)
            {
                return true;
            }

            if (!IsTransitionAllowed(current, nextStage))
            {
                MarkTemporalInvariantLocked(
                    name: "stage_transition_valid",
                    passed: false,
                    expected: $"{current} -> {nextStage} allowed",
                    actual: $"rejected transition ({reason})");
                return false;
            }

            _currentStage = nextStage;
            _stageTransitions.Add(
                new StageTransitionEvent(
                    TimestampUtc: DateTimeOffset.UtcNow.ToString("O"),
                    FromStage: current,
                    ToStage: nextStage,
                    Reason: reason));
            return true;
        }

    }

    public bool ValidateClientOpcode(uint opcode, bool strictEnforcement, out string? error)
    {
        error = null;
        lock (_stageSync)
        {
            if (opcode == ClientOpcodeEnterEncryptedModeAck && _currentStage < BridgeStage.ENTER_ENCRYPTED_SENT)
            {
                string actual = $"opcode=0x{opcode:X8} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "client_ack_after_enter_encrypted_sent",
                    passed: false,
                    expected: "ACK only after ENTER_ENCRYPTED_SENT",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected ACK opcode in stage {_currentStage}.";
                    return false;
                }
            }

            if (opcode == ClientOpcodeEnumCharacters && _currentStage < BridgeStage.BOOTSTRAP_FLUSHED)
            {
                string actual = $"opcode=0x{opcode:X8} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "client_char_enum_after_bootstrap_flushed",
                    passed: false,
                    expected: "CHAR_ENUM request only after BOOTSTRAP_FLUSHED",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected CMSG_ENUM_CHARACTERS in stage {_currentStage}.";
                    return false;
                }
            }
        }

        return true;
    }

    public bool ValidateServerOpcode(ushort opcode, bool strictEnforcement, out string? error)
    {
        error = null;
        lock (_stageSync)
        {
            if (opcode == ServerOpcodeAuthResponse && _currentStage < BridgeStage.AUTH_SESSION_BRIDGED)
            {
                string actual = $"opcode=0x{opcode:X4} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "server_auth_response_after_auth_session_bridged",
                    passed: false,
                    expected: "SMSG_AUTH_RESPONSE only after AUTH_SESSION_BRIDGED",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected SMSG_AUTH_RESPONSE in stage {_currentStage}.";
                    return false;
                }
            }

            if (opcode == ServerOpcodeCharEnum && _currentStage < BridgeStage.CHAR_ENUM_REQUESTED)
            {
                string actual = $"opcode=0x{opcode:X4} in stage={_currentStage}";
                MarkTemporalInvariantLocked(
                    name: "server_char_enum_after_char_enum_requested",
                    passed: false,
                    expected: "SMSG_CHAR_ENUM only after CHAR_ENUM_REQUESTED",
                    actual: actual);

                if (strictEnforcement)
                {
                    error = $"Unexpected SMSG_CHAR_ENUM in stage {_currentStage}.";
                    return false;
                }
            }
        }

        return true;
    }

    public void MarkTemporalInvariant(string name, bool passed, string expected, string actual)
    {
        lock (_stageSync)
        {
            MarkTemporalInvariantLocked(name, passed, expected, actual);
        }
    }

    public IReadOnlyList<StageTransitionEvent> GetStageTransitions()
    {
        lock (_stageSync)
        {
            return _stageTransitions.ToArray();
        }
    }

    public IReadOnlyList<TemporalInvariantResult> GetTemporalInvariants()
    {
        lock (_stageSync)
        {
            return _temporalInvariants.ToArray();
        }
    }

    public bool TryGetFirstDivergence(out FirstDivergenceRecord divergence)
    {
        lock (_stageSync)
        {
            if (_firstDivergence is not null)
            {
                divergence = _firstDivergence.Value;
                return true;
            }
        }

        divergence = default;
        return false;
    }

    public string FailureClassTarget
    {
        get
        {
            lock (_stageSync)
            {
                return _failureClassTarget ?? "<unknown>";
            }
        }
    }

    public string ActiveLayer
    {
        get
        {
            lock (_stageSync)
            {
                return _activeLayer ?? "<unknown>";
            }
        }
    }

    public string ParityAxis
    {
        get
        {
            lock (_stageSync)
            {
                return _parityAxis ?? "<unknown>";
            }
        }
    }

    public string ResolveFailureClass()
    {
        if (TryGetDisconnect(out uint reason, out _))
        {
            if (reason == 3)
            {
                return "reason=3";
            }

            if (reason == 24)
            {
                return "reason=24";
            }

            return $"reason={reason}";
        }

        if (HasFailedInvariant("db_parity_gate"))
        {
            return "db_mismatch";
        }

        if (HasFailedInvariant("stage_transition_valid") ||
            HasFailedInvariant("client_ack_after_enter_encrypted_sent") ||
            HasFailedInvariant("client_char_enum_after_bootstrap_flushed") ||
            HasFailedInvariant("server_auth_response_after_auth_session_bridged") ||
            HasFailedInvariant("server_char_enum_after_char_enum_requested"))
        {
            return "reason=3";
        }

        if (TryGetAckTimeout(out _, out _))
        {
            return "no ACK";
        }

        return CurrentStage >= BridgeStage.CHAR_ENUM_RECEIVED ? "none" : "inconclusive";
    }

    private bool HasFailedInvariant(string invariantName)
    {
        lock (_stageSync)
        {
            foreach (TemporalInvariantResult invariant in _temporalInvariants)
            {
                if (!invariant.Passed &&
                    string.Equals(invariant.Name, invariantName, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsTransitionAllowed(BridgeStage current, BridgeStage next)
    {
        return current switch
        {
            BridgeStage.PRE_AUTH => next == BridgeStage.AUTH_SESSION_BRIDGED,
            BridgeStage.AUTH_SESSION_BRIDGED => next == BridgeStage.ENTER_ENCRYPTED_SENT,
            BridgeStage.ENTER_ENCRYPTED_SENT => next == BridgeStage.WORLD_CRYPT_ACTIVE || next == BridgeStage.BOOTSTRAP_FLUSHED,
            BridgeStage.WORLD_CRYPT_ACTIVE => next == BridgeStage.BOOTSTRAP_FLUSHED,
            BridgeStage.BOOTSTRAP_FLUSHED => next == BridgeStage.CHAR_ENUM_REQUESTED,
            BridgeStage.CHAR_ENUM_REQUESTED => next == BridgeStage.CHAR_ENUM_REQUESTED || next == BridgeStage.CHAR_ENUM_RECEIVED,
            BridgeStage.CHAR_ENUM_RECEIVED => next == BridgeStage.CHAR_ENUM_REQUESTED,
            _ => false
        };
    }

    private void MarkTemporalInvariantLocked(string name, bool passed, string expected, string actual)
    {
        _temporalInvariants.Add(
            new TemporalInvariantResult(
                Name: name,
                Passed: passed,
                Expected: expected,
                Actual: actual,
                TimestampUtc: DateTimeOffset.UtcNow.ToString("O")));
    }

    private void TryCaptureFirstDivergenceFromDiffPath(string diffPath)
    {
        if (string.IsNullOrWhiteSpace(diffPath) || !File.Exists(diffPath))
        {
            return;
        }

        try
        {
            foreach (string line in File.ReadLines(diffPath, Encoding.UTF8))
            {
                if (!line.StartsWith("idx=", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!TryParseFirstDiffLine(line, out int offset, out string? expected, out string? actual))
                {
                    continue;
                }

                lock (_stageSync)
                {
                    _firstDivergence = new FirstDivergenceRecord(
                        Offset: offset,
                        Layer: _activeLayer ?? "Payload",
                        ParityAxis: _parityAxis ?? "layout parity",
                        ExpectedBytes: expected,
                        ActualBytes: actual,
                        SourcePath: diffPath,
                        TimestampUtc: DateTimeOffset.UtcNow.ToString("O"));
                }

                return;
            }
        }
        catch (IOException)
        {
            // Best-effort evidence extraction only.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort evidence extraction only.
        }
    }

    private static bool TryParseFirstDiffLine(string line, out int offset, out string? expected, out string? actual)
    {
        offset = -1;
        expected = null;
        actual = null;

        // Format: idx=0: expected=01 actual=00
        int idxEq = line.IndexOf('=');
        int idxColon = line.IndexOf(':');
        if (idxEq < 0 || idxColon < 0 || idxColon <= idxEq + 1)
        {
            return false;
        }

        string offsetText = line.Substring(idxEq + 1, idxColon - idxEq - 1).Trim();
        if (!int.TryParse(offsetText, NumberStyles.Integer, CultureInfo.InvariantCulture, out offset))
        {
            return false;
        }

        string tail = line.Substring(idxColon + 1);
        string[] parts = tail.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (string part in parts)
        {
            if (part.StartsWith("expected=", StringComparison.OrdinalIgnoreCase))
            {
                expected = part.Substring("expected=".Length).Trim();
                continue;
            }

            if (part.StartsWith("actual=", StringComparison.OrdinalIgnoreCase))
            {
                actual = part.Substring("actual=".Length).Trim();
            }
        }

        return true;
    }

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

internal readonly record struct RetailAuthSessionFrame(
    ulong DosResponse,
    uint RegionId,
    uint BattlegroupId,
    uint RealmId,
    byte[] LocalChallenge4,
    byte[] LocalChallenge32,
    int AccountId,
    int RawFrameBytes);

internal readonly record struct RetailFrameChunk(
    byte[] Frame,
    uint Opcode,
    int BodyLength);

internal readonly record struct AcoreSessionMaterial(
    int AccountId,
    string AccountName,
    byte[] SessionKey,
    byte[]? BnetKeyData64,
    byte Expansion,
    bool Locked);

internal readonly record struct DbParityGateResult(
    bool Passed,
    string FailureReason,
    string Expected,
    string Actual);

internal readonly record struct ProofPackArtifacts(
    string HexPath,
    string MetadataJsonPath,
    string DiffPath);

internal readonly record struct AuthChallengeProofArtifacts(
    string HexPath,
    string MetadataJsonPath);

internal readonly record struct EnterEncryptedModeProof(
    string TimestampUtc,
    uint RetailOpcode,
    int RegionGroup,
    bool IncludeRegionGroup,
    bool Enabled,
    bool EnabledAsByte,
    bool SignatureFirst,
    bool PreferBnetKeyData,
    string KeySource,
    string WireFormat,
    string SessionKeySha256,
    string? BnetKeyDataSha256,
    string? BnetKeyDerivationError,
    string? RetailWorldEncryptKeySha256,
    string? RetailWorldEncryptKeyHex,
    string LocalChallengeHex,
    string ServerChallengeHex,
    string ToSignHex,
    string SignatureHex,
    string PayloadHex,
    int PayloadBytes);

internal readonly record struct RetailAuthChallengeProof(
    string TimestampUtc,
    uint RetailOpcode,
    uint AcoreDosChallenge,
    uint AcoreAuthSeed,
    string AcoreNewSeedHex,
    string DosBlockSource,
    string DosBlockHex,
    string ChallengeBlockHex,
    string RetailPayloadHex,
    int RetailPayloadBytes);

internal readonly record struct EnterEncryptedPayloadParityResult(
    bool FixtureFound,
    bool PayloadMatch,
    string FixturePath,
    int ExpectedLength,
    int ActualLength,
    int DiffCount,
    int? FirstDiffIndex,
    byte? FirstExpectedByte,
    byte? FirstActualByte,
    bool SignatureBytesIgnored,
    int? SignatureOffset,
    int SignatureBytes,
    string? Error);

internal readonly record struct DeferredFrameParityResult(
    string Status,
    string? FixturePath,
    int? DiffOffset,
    string? ExpectedBytes,
    string? ActualBytes);

