using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

internal sealed partial class WorldProxyBridgeState
{
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
        string retailWorldPacketCryptNonceLayout = WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultNonceLayout,
        string retailWorldPacketCryptServerNonceMagic = WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultServerNonceMagic,
        string retailWorldPacketCryptClientNonceMagic = WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultClientNonceMagic)
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
