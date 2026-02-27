using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MySqlConnector;

namespace Adapter.WorldGateway;

/// <summary>
/// Low-latency bidirectional TCP proxy (Retail client <-> AzerothCore world).
/// Uses System.IO.Pipelines for high-throughput stream forwarding.
/// </summary>
public sealed class WorldProxyListener : BackgroundService
{
    private const int DefaultDumpBytes = 64;
    private const uint RetailOpcodeAuthSession = 0x0041_0001;
    private const uint RetailOpcodeEnterEncryptedModeAck = 0x0041_0005;
    private const uint RetailOpcodePing = 0x0041_0006;
    private const uint RetailOpcodeLogDisconnect = 0x0041_0007;
    private const uint RetailOpcodeCmsgDbQueryBulk = 0x0040_0010;
    private const uint RetailOpcodeCmsgHotfixRequest = 0x0040_0011;
    private const uint RetailOpcodeCmsgBattlePayGetProductList = 0x0040_00E9;
    private const uint RetailOpcodeCmsgBattlePayGetPurchaseList = 0x0040_00EA;
    private const uint RetailOpcodeCmsgGetUndeleteCharacterCooldownStatus = 0x0040_010F;
    private const uint RetailOpcodeCmsgUpdateVasPurchaseStates = 0x0040_0123;
    private const uint RetailOpcodeCmsgSocialContractRequest = 0x0040_0176;
    private const uint RetailOpcodeCmsgQuickJoinAutoAcceptRequests = 0x0040_0132;
    private const uint RetailOpcodeCmsgGetLastCatalogFetch = 0x0029_0036;
    private const uint RetailOpcodeCmsgServerTimeOffsetRequest = 0x0040_00CA;
    private const uint RetailOpcodeCmsgBattlenetRequest = 0x0040_0124;
    private const uint RetailOpcodeEnumCharacters = 0x0040_0014;
    private const uint RetailOpcodeWarden3Data = 0x0040_0018;
    private const uint RetailOpcodeCmsgAddonList = 0x0040_0004;
    private const uint RetailOpcodeKeepAlive = 0x0040_00AB;
    private const uint RetailOpcodeTimeSyncResponse = 0x003E_005C;
    private const uint RetailOpcodeSmsgAuthResponse = 0x0042_0001;
    private const uint RetailOpcodeSmsgAuthResponseSweepStart = 0x0042_0000;
    private const int RetailOpcodeSmsgAuthResponseSweepCount = 0x0101;
    private const uint RetailOpcodeSmsgPong = 0x0049_0009;
    private const uint RetailOpcodeSmsgCompressedPacket = 0x0049_000D;
    private const uint RetailOpcodeSmsgEnterEncryptedModeDefault = 0x0049_0004;
    private const uint RetailOpcodeSmsgTimeSyncRequest = 0x005A_0000;
    private const uint RetailOpcodeSmsgFeatureSystemStatusGlueScreen = 0x0042_0063;
    private const uint RetailOpcodeSmsgMirrorVars = 0x0042_036A;
    private const uint RetailOpcodeSmsgSetTimeZoneInformation = 0x0042_0121;
    private const uint RetailOpcodeSmsgEnumCharactersResult = 0x0042_0018;
    private const uint RetailOpcodeSmsgWarden3Data = 0x0042_000B;
    private const uint RetailOpcodeSmsgAddonListRequest = 0x0042_00EA;
    private const uint RetailOpcodeSmsgCacheVersion = 0x0046_000E;
    private const uint RetailOpcodeSmsgDbReply = 0x0046_0000;
    private const uint RetailOpcodeSmsgAvailableHotfixes = 0x0046_0001;
    private const uint RetailOpcodeSmsgHotfixConnect = 0x0046_0003;
    private const uint RetailOpcodeSmsgAccountDataTimes = 0x0042_01B4;
    private const uint RetailOpcodeSmsgServerTimeOffset = 0x0042_01BE;
    private const uint RetailOpcodeSmsgTutorialFlags = 0x0042_0266;
    private const uint RetailOpcodeSmsgAccountItemCollectionData = 0x0042_035B;
    private const uint RetailOpcodeSmsgBattleNetResponse = 0x0042_02AD;
    private const uint RetailOpcodeSmsgBattleNetConnectionStatus = 0x0042_02AF;
    private const uint RetailOpcodeSmsgUndeleteCooldownStatusResponse = 0x0042_0274;
    private const uint RetailOpcodeSmsgSocialContractRequestResponse = 0x0042_0323;
    private const uint RetailOpcodeSmsgAuthSequencePrelude = 0x4077_0E75;
    private const uint AcoreOpcodeAuthSession = 0x0000_01ED;
    private const uint AcoreOpcodeCharEnum = 0x0000_0037;
    private const uint AcoreOpcodePing = 0x0000_01DC;
    private const uint AcoreOpcodeWardenData = 0x0000_02E7;
    private const uint AcoreOpcodeTimeSyncResp = 0x0000_0391;
    private const uint AcoreOpcodeKeepAlive = 0x0000_0407;
    private const ushort AcoreOpcodeAuthChallenge = 0x01EC;
    private const ushort AcoreOpcodeSmsgAuthResponse = 0x01EE;
    private const ushort AcoreOpcodeSmsgCharEnum = 0x003B;
    private const ushort AcoreOpcodeSmsgPong = 0x01DD;
    private const ushort AcoreOpcodeSmsgTimeSyncRequest = 0x0390;
    private const ushort AcoreOpcodeSmsgWardenData = 0x02E6;
    private const ushort AcoreOpcodeSmsgAddonInfo = 0x02EF;
    private const ushort AcoreOpcodeSmsgClientCacheVersion = 0x04AB;
    private const ushort AcoreOpcodeSmsgTutorialFlags = 0x00FD;
    private const int AcoreSessionKeyBytes = 40;
    private const int AcoreDigestBytes = 20;
    private const int RetailDigestBytes = 24;
    private const int RetailAuthFixedPayloadBytes = 8 + 4 + 4 + 4 + 32 + RetailDigestBytes;
    private const int RetailAccountDataTimesCount = 20;
    private const int RetailTutorialValuesCount = 8;
    private static readonly byte[] Sha1ZeroPrefix = [0, 0, 0, 0];
    private static readonly byte[] ServerConnectionInitializer = Encoding.ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2\n");
    private static readonly byte[] ClientConnectionInitializer = Encoding.ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2\n");
    private const uint TrinityCompressionAdlerSeed = 0x9827D8F1;
    private const int TrinityCompressionThresholdBytes = 0x400;
    private const int AuthResponseReplayOptionalBitsOffset = 4;
    private const byte AuthResponseReplaySuccessInfoMask = 0x80;
    private const byte AuthResponseReplayWaitInfoMask = 0x40;
    private const byte AuthResponseReplaySuccessInfoCurrentBuildMask = 0x04;
    private const uint AuthResponseReplayCurrentBuildValue = 66102;
    private const int AuthResponseReplayWaitInfoPayloadBytes = 10;
    private const int AuthResponseReplaySuccessInfoOffset = 5;
    private const int AuthResponseReplayTopVirtualRealmAddressOffset = AuthResponseReplaySuccessInfoOffset + 0;
    private const int AuthResponseReplayActiveExpansionLevelOffset = AuthResponseReplaySuccessInfoOffset + 12;
    private const int AuthResponseReplayAccountExpansionLevelOffset = AuthResponseReplaySuccessInfoOffset + 13;
    private const int AuthResponseReplayAvailableClassesCountOffset = AuthResponseReplaySuccessInfoOffset + 18;
    private const int AuthResponseReplayClassMatrixStartOffset = AuthResponseReplaySuccessInfoOffset + 38;
    private const uint AuthResponseReplayMaxAvailableClassesRows = 4096;
    private const uint AuthResponseReplayMaxClassRowsPerRace = 4096;
    private const int AuthResponseReplayTimeFieldOffset = AuthResponseReplaySuccessInfoOffset + 30;
    private readonly ILogger<WorldProxyListener> _logger;
    private readonly WorldProxyOptions _options;
    private readonly ProtocolEngineeringOptions _protocolOptions;
    private readonly AckPolicyMode _ackPolicyMode;
    private readonly BootstrapFlushTriggerMode _bootstrapFlushTriggerMode;
    private readonly bool _bootstrapFlushTriggerModeValid;
    private readonly uint _enterEncryptedModeOpcode;
    private readonly bool _enterEncryptedModeOpcodeValid;
    private readonly uint _probeAuthResponseOpcode;
    private readonly bool _probeAuthResponseOpcodeOverrideProvided;
    private readonly bool _probeAuthResponseOpcodeOverrideValid;
    private readonly AuthResponseFuzzMutation _authResponseFuzzMutation;
    private readonly bool _authResponseFuzzPlanRecognized;
    private readonly HashSet<uint> _probeDropDeferredOpcodes = new();
    private readonly bool _probeDropDeferredOpcodeConfigProvided;
    private readonly string? _probeDropDeferredOpcodeParseError;
    private readonly byte[] _probeRetailSequencePreludePayload = [0, 0, 0, 0];
    private readonly bool _probeRetailSequencePreludePayloadProvided;
    private readonly bool _probeRetailSequencePreludePayloadValid;
    private readonly string? _probeRetailSequencePreludePayloadParseError;
    private readonly byte[] _probeAuthResponseReplayPayload = Array.Empty<byte>();
    private readonly bool _probeAuthResponseReplayPayloadProvided;
    private readonly bool _probeAuthResponseReplayPayloadValid;
    private readonly string? _probeAuthResponseReplayPayloadParseError;
    private readonly string? _probeAuthResponseReplayPayloadResolvedPath;
    private readonly byte[] _probeAuthResponseReplayCompressedPayload = Array.Empty<byte>();
    private readonly bool _probeAuthResponseReplayCompressedPayloadProvided;
    private readonly bool _probeAuthResponseReplayCompressedPayloadValid;
    private readonly string? _probeAuthResponseReplayCompressedPayloadParseError;
    private readonly string? _probeAuthResponseReplayCompressedPayloadResolvedPath;
    private readonly bool _probeAuthResponseReplayPatchTimeToNow;
    private readonly bool _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount;
    private readonly bool _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount;
    private readonly bool _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset;
    private readonly bool _probeAuthResponseReplayPatchCurrentBuildPresent;
    private readonly bool _probeAuthResponseReplayPatchWaitInfoPresent;
    private readonly bool _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm;
    private readonly bool _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm;
    private readonly bool _probeAuthResponseReplayBisectionResultOnlyErrorOk;
    private readonly byte[] _probeSetTimeZoneInformationPayload = Array.Empty<byte>();
    private readonly bool _probeSetTimeZoneInformationPayloadProvided;
    private readonly bool _probeSetTimeZoneInformationPayloadValid;
    private readonly string? _probeSetTimeZoneInformationPayloadParseError;
    private readonly string? _probeSetTimeZoneInformationPayloadResolvedPath;
    private readonly byte[] _probeFeatureSystemStatusGlueScreenPayload = Array.Empty<byte>();
    private readonly bool _probeFeatureSystemStatusGlueScreenPayloadProvided;
    private readonly bool _probeFeatureSystemStatusGlueScreenPayloadValid;
    private readonly string? _probeFeatureSystemStatusGlueScreenPayloadParseError;
    private readonly string? _probeFeatureSystemStatusGlueScreenPayloadResolvedPath;
    private readonly byte[] _probeMirrorVarsPayload = Array.Empty<byte>();
    private readonly bool _probeMirrorVarsPayloadProvided;
    private readonly bool _probeMirrorVarsPayloadValid;
    private readonly string? _probeMirrorVarsPayloadParseError;
    private readonly string? _probeMirrorVarsPayloadResolvedPath;
    private readonly byte[] _probeCacheVersionPayload = Array.Empty<byte>();
    private readonly bool _probeCacheVersionPayloadProvided;
    private readonly bool _probeCacheVersionPayloadValid;
    private readonly string? _probeCacheVersionPayloadParseError;
    private readonly string? _probeCacheVersionPayloadResolvedPath;
    private readonly byte[] _probeAvailableHotfixesPayload = Array.Empty<byte>();
    private readonly bool _probeAvailableHotfixesPayloadProvided;
    private readonly bool _probeAvailableHotfixesPayloadValid;
    private readonly string? _probeAvailableHotfixesPayloadParseError;
    private readonly string? _probeAvailableHotfixesPayloadResolvedPath;
    private readonly byte[] _probeAccountDataTimesPayload = Array.Empty<byte>();
    private readonly bool _probeAccountDataTimesPayloadProvided;
    private readonly bool _probeAccountDataTimesPayloadValid;
    private readonly string? _probeAccountDataTimesPayloadParseError;
    private readonly string? _probeAccountDataTimesPayloadResolvedPath;
    private readonly byte[] _probeTutorialFlagsPayload = Array.Empty<byte>();
    private readonly bool _probeTutorialFlagsPayloadProvided;
    private readonly bool _probeTutorialFlagsPayloadValid;
    private readonly string? _probeTutorialFlagsPayloadParseError;
    private readonly string? _probeTutorialFlagsPayloadResolvedPath;
    private readonly byte[] _probeBattleNetConnectionStatusPayload = Array.Empty<byte>();
    private readonly bool _probeBattleNetConnectionStatusPayloadProvided;
    private readonly bool _probeBattleNetConnectionStatusPayloadValid;
    private readonly string? _probeBattleNetConnectionStatusPayloadParseError;
    private readonly string? _probeBattleNetConnectionStatusPayloadResolvedPath;

    private readonly object _activeConnectionsLock = new();
    private readonly List<Task> _activeConnections = new();
    private readonly ConcurrentDictionary<string, long> _reconnectCooldownUntilByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly WorldSessionMaterialRepository _worldSessionMaterialRepository;
    private TcpListener? _listener;
    private int _connectionSequence;

    public WorldProxyListener(
        ILogger<WorldProxyListener> logger,
        IOptions<WorldProxyOptions> options,
        IOptions<ProtocolEngineeringOptions> protocolOptions)
    {
        _logger = logger;
        _options = options.Value;
        _protocolOptions = protocolOptions.Value;
        _worldSessionMaterialRepository = new WorldSessionMaterialRepository(
            _logger,
            _options.AuthDbConnectionString,
            AcoreSessionKeyBytes,
            maxReadAttempts: 3,
            retryBaseDelayMs: 150,
            selectCommandTimeoutSeconds: 5);
        _probeAuthResponseReplayPatchTimeToNow = _options.ProbeAuthResponseReplayPatchTimeToNow;
        _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount = _options.ProbeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount;
        _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount = _options.ProbeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount;
        _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset = _options.ProbeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset;
        _probeAuthResponseReplayPatchCurrentBuildPresent = _options.ProbeAuthResponseReplayPatchCurrentBuildPresent;
        _probeAuthResponseReplayPatchWaitInfoPresent = _options.ProbeAuthResponseReplayPatchWaitInfoPresent;
        _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm = _options.ProbeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm;
        _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm = _options.ProbeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm;
        _probeAuthResponseReplayBisectionResultOnlyErrorOk = _options.ProbeAuthResponseReplayBisectionResultOnlyErrorOk;
        _ackPolicyMode = AckPolicyResolver.Parse(_protocolOptions.AckPolicy);
        _bootstrapFlushTriggerMode = ParseBootstrapFlushTriggerMode(
            _options.BootstrapFlushTriggerSource,
            out _bootstrapFlushTriggerModeValid);
        _enterEncryptedModeOpcodeValid = TryParseFlexibleUInt32(_options.EnterEncryptedModeOpcode, out _enterEncryptedModeOpcode);
        _probeAuthResponseOpcode = RetailOpcodeSmsgAuthResponse;
        if (!_enterEncryptedModeOpcodeValid)
        {
            _enterEncryptedModeOpcode = RetailOpcodeSmsgEnterEncryptedModeDefault;
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeAuthResponseOpcodeOverride))
        {
            _probeAuthResponseOpcodeOverrideProvided = true;
            _probeAuthResponseOpcodeOverrideValid = TryParseFlexibleUInt32(
                _options.ProbeAuthResponseOpcodeOverride,
                out uint parsedAuthOpcode);
            if (_probeAuthResponseOpcodeOverrideValid)
            {
                _probeAuthResponseOpcode = parsedAuthOpcode;
            }
        }

        _authResponseFuzzMutation = AuthResponseFuzzMutationResolver.Resolve(
            _options.ProbeAuthResponseFuzzerEnabled,
            _options.ProbeAuthResponseFuzzerPlan,
            _options.ProbeAuthResponseFuzzerIteration,
            RetailOpcodeSmsgAuthResponseSweepStart,
            RetailOpcodeSmsgAuthResponseSweepCount,
            out _authResponseFuzzPlanRecognized);
        if (_authResponseFuzzMutation.Enabled && _authResponseFuzzMutation.OpcodeOverride is uint fuzzOpcode)
        {
            _probeAuthResponseOpcode = fuzzOpcode;
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeDropDeferredOpcode))
        {
            _probeDropDeferredOpcodeConfigProvided = true;
            if (!TryParseProbeDropDeferredOpcodes(
                    _options.ProbeDropDeferredOpcode,
                    _probeDropDeferredOpcodes,
                    out string? parseError))
            {
                _probeDropDeferredOpcodeParseError = parseError;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeRetailSequencePreludePayloadHex))
        {
            _probeRetailSequencePreludePayloadProvided = true;
            _probeRetailSequencePreludePayloadValid = HexPayloadLoader.TryParseFixedLengthHex(
                _options.ProbeRetailSequencePreludePayloadHex,
                expectedLengthBytes: 4,
                out byte[] parsedPreludePayload,
                out string? preludeParseError);
            if (_probeRetailSequencePreludePayloadValid)
            {
                _probeRetailSequencePreludePayload = parsedPreludePayload;
            }
            else
            {
                _probeRetailSequencePreludePayloadParseError = preludeParseError;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeAuthResponseReplayPayloadHexPath))
        {
            _probeAuthResponseReplayPayloadProvided = true;
            _probeAuthResponseReplayPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeAuthResponseReplayPayloadHexPath,
                out byte[] parsedAuthResponsePayload,
                out string? replayPayloadError,
                out string? resolvedReplayPayloadPath);
            if (_probeAuthResponseReplayPayloadValid)
            {
                _probeAuthResponseReplayPayload = parsedAuthResponsePayload;
                _probeAuthResponseReplayPayloadResolvedPath = resolvedReplayPayloadPath;
            }
            else
            {
                _probeAuthResponseReplayPayloadParseError = replayPayloadError;
                _probeAuthResponseReplayPayloadResolvedPath = resolvedReplayPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeAuthResponseReplayCompressedPayloadHexPath))
        {
            _probeAuthResponseReplayCompressedPayloadProvided = true;
            _probeAuthResponseReplayCompressedPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeAuthResponseReplayCompressedPayloadHexPath,
                out byte[] parsedCompressedAuthResponsePayload,
                out string? replayCompressedPayloadError,
                out string? resolvedReplayCompressedPayloadPath);
            if (_probeAuthResponseReplayCompressedPayloadValid)
            {
                _probeAuthResponseReplayCompressedPayload = parsedCompressedAuthResponsePayload;
                _probeAuthResponseReplayCompressedPayloadResolvedPath = resolvedReplayCompressedPayloadPath;
            }
            else
            {
                _probeAuthResponseReplayCompressedPayloadParseError = replayCompressedPayloadError;
                _probeAuthResponseReplayCompressedPayloadResolvedPath = resolvedReplayCompressedPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeSetTimeZoneInformationPayloadHexPath))
        {
            _probeSetTimeZoneInformationPayloadProvided = true;
            _probeSetTimeZoneInformationPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeSetTimeZoneInformationPayloadHexPath,
                out byte[] parsedTimeZonePayload,
                out string? timeZonePayloadError,
                out string? resolvedTimeZonePayloadPath);
            if (_probeSetTimeZoneInformationPayloadValid)
            {
                _probeSetTimeZoneInformationPayload = parsedTimeZonePayload;
                _probeSetTimeZoneInformationPayloadResolvedPath = resolvedTimeZonePayloadPath;
            }
            else
            {
                _probeSetTimeZoneInformationPayloadParseError = timeZonePayloadError;
                _probeSetTimeZoneInformationPayloadResolvedPath = resolvedTimeZonePayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeFeatureSystemStatusGlueScreenPayloadHexPath))
        {
            _probeFeatureSystemStatusGlueScreenPayloadProvided = true;
            _probeFeatureSystemStatusGlueScreenPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeFeatureSystemStatusGlueScreenPayloadHexPath,
                out byte[] parsedFeaturePayload,
                out string? featurePayloadError,
                out string? resolvedFeaturePayloadPath);
            if (_probeFeatureSystemStatusGlueScreenPayloadValid)
            {
                _probeFeatureSystemStatusGlueScreenPayload = parsedFeaturePayload;
                _probeFeatureSystemStatusGlueScreenPayloadResolvedPath = resolvedFeaturePayloadPath;
            }
            else
            {
                _probeFeatureSystemStatusGlueScreenPayloadParseError = featurePayloadError;
                _probeFeatureSystemStatusGlueScreenPayloadResolvedPath = resolvedFeaturePayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeMirrorVarsPayloadHexPath))
        {
            _probeMirrorVarsPayloadProvided = true;
            _probeMirrorVarsPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeMirrorVarsPayloadHexPath,
                out byte[] parsedMirrorVarsPayload,
                out string? mirrorVarsPayloadError,
                out string? resolvedMirrorVarsPayloadPath);
            if (_probeMirrorVarsPayloadValid)
            {
                _probeMirrorVarsPayload = parsedMirrorVarsPayload;
                _probeMirrorVarsPayloadResolvedPath = resolvedMirrorVarsPayloadPath;
            }
            else
            {
                _probeMirrorVarsPayloadParseError = mirrorVarsPayloadError;
                _probeMirrorVarsPayloadResolvedPath = resolvedMirrorVarsPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeCacheVersionPayloadHexPath))
        {
            _probeCacheVersionPayloadProvided = true;
            _probeCacheVersionPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeCacheVersionPayloadHexPath,
                out byte[] parsedCacheVersionPayload,
                out string? cacheVersionPayloadError,
                out string? resolvedCacheVersionPayloadPath);
            if (_probeCacheVersionPayloadValid)
            {
                _probeCacheVersionPayload = parsedCacheVersionPayload;
                _probeCacheVersionPayloadResolvedPath = resolvedCacheVersionPayloadPath;
            }
            else
            {
                _probeCacheVersionPayloadParseError = cacheVersionPayloadError;
                _probeCacheVersionPayloadResolvedPath = resolvedCacheVersionPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeAvailableHotfixesPayloadHexPath))
        {
            _probeAvailableHotfixesPayloadProvided = true;
            _probeAvailableHotfixesPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeAvailableHotfixesPayloadHexPath,
                out byte[] parsedAvailableHotfixesPayload,
                out string? availableHotfixesPayloadError,
                out string? resolvedAvailableHotfixesPayloadPath);
            if (_probeAvailableHotfixesPayloadValid)
            {
                _probeAvailableHotfixesPayload = parsedAvailableHotfixesPayload;
                _probeAvailableHotfixesPayloadResolvedPath = resolvedAvailableHotfixesPayloadPath;
            }
            else
            {
                _probeAvailableHotfixesPayloadParseError = availableHotfixesPayloadError;
                _probeAvailableHotfixesPayloadResolvedPath = resolvedAvailableHotfixesPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeAccountDataTimesPayloadHexPath))
        {
            _probeAccountDataTimesPayloadProvided = true;
            _probeAccountDataTimesPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeAccountDataTimesPayloadHexPath,
                out byte[] parsedAccountDataTimesPayload,
                out string? accountDataTimesPayloadError,
                out string? resolvedAccountDataTimesPayloadPath);
            if (_probeAccountDataTimesPayloadValid)
            {
                _probeAccountDataTimesPayload = parsedAccountDataTimesPayload;
                _probeAccountDataTimesPayloadResolvedPath = resolvedAccountDataTimesPayloadPath;
            }
            else
            {
                _probeAccountDataTimesPayloadParseError = accountDataTimesPayloadError;
                _probeAccountDataTimesPayloadResolvedPath = resolvedAccountDataTimesPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeTutorialFlagsPayloadHexPath))
        {
            _probeTutorialFlagsPayloadProvided = true;
            _probeTutorialFlagsPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeTutorialFlagsPayloadHexPath,
                out byte[] parsedTutorialFlagsPayload,
                out string? tutorialFlagsPayloadError,
                out string? resolvedTutorialFlagsPayloadPath);
            if (_probeTutorialFlagsPayloadValid)
            {
                _probeTutorialFlagsPayload = parsedTutorialFlagsPayload;
                _probeTutorialFlagsPayloadResolvedPath = resolvedTutorialFlagsPayloadPath;
            }
            else
            {
                _probeTutorialFlagsPayloadParseError = tutorialFlagsPayloadError;
                _probeTutorialFlagsPayloadResolvedPath = resolvedTutorialFlagsPayloadPath;
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeBattleNetConnectionStatusPayloadHexPath))
        {
            _probeBattleNetConnectionStatusPayloadProvided = true;
            _probeBattleNetConnectionStatusPayloadValid = HexPayloadLoader.TryLoadHexPayloadFromFile(
                _options.ProbeBattleNetConnectionStatusPayloadHexPath,
                out byte[] parsedBattleNetConnectionStatusPayload,
                out string? battleNetConnectionStatusPayloadError,
                out string? resolvedBattleNetConnectionStatusPayloadPath);
            if (_probeBattleNetConnectionStatusPayloadValid)
            {
                _probeBattleNetConnectionStatusPayload = parsedBattleNetConnectionStatusPayload;
                _probeBattleNetConnectionStatusPayloadResolvedPath = resolvedBattleNetConnectionStatusPayloadPath;
            }
            else
            {
                _probeBattleNetConnectionStatusPayloadParseError = battleNetConnectionStatusPayloadError;
                _probeBattleNetConnectionStatusPayloadResolvedPath = resolvedBattleNetConnectionStatusPayloadPath;
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        ValidateProtocolExperimentContractOrThrow();

        IPAddress bindAddress = ParseBindAddress(_options.ListenAddress);
        bool resolvedAckGate = ResolveEffectiveAckGate(out string ackGateSource);
        _listener = new TcpListener(bindAddress, _options.ListenPort);
        _listener.Server.NoDelay = true;
        _listener.Start(_options.Backlog);

        if (!_enterEncryptedModeOpcodeValid)
        {
            _logger.LogWarning(
                "WorldProxy option EnterEncryptedModeOpcode is invalid ('{ConfiguredValue}'). Falling back to default 0x{DefaultOpcode:X8}.",
                _options.EnterEncryptedModeOpcode,
                RetailOpcodeSmsgEnterEncryptedModeDefault);
        }

        if (_probeAuthResponseOpcodeOverrideProvided && !_probeAuthResponseOpcodeOverrideValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeAuthResponseOpcodeOverride is invalid ('{ConfiguredValue}'). Falling back to default 0x{DefaultOpcode:X8}.",
                _options.ProbeAuthResponseOpcodeOverride,
                RetailOpcodeSmsgAuthResponse);
        }

        if (_probeAuthResponseOpcode != RetailOpcodeSmsgAuthResponse)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_RESPONSE opcode override active (0x{Opcode:X8}).",
                _probeAuthResponseOpcode);
        }

        if (_probeDropDeferredOpcodeConfigProvided && _probeDropDeferredOpcodes.Count == 0)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeDropDeferredOpcode is invalid ('{ConfiguredValue}'). Deferred-frame drop probe disabled. Error={Error}",
                _options.ProbeDropDeferredOpcode,
                _probeDropDeferredOpcodeParseError ?? "<unknown>");
        }

        if (_probeRetailSequencePreludePayloadProvided && !_probeRetailSequencePreludePayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeRetailSequencePreludePayloadHex is invalid ('{ConfiguredValue}'). Falling back to default 00000000. Error={Error}",
                _options.ProbeRetailSequencePreludePayloadHex,
                _probeRetailSequencePreludePayloadParseError ?? "<unknown>");
        }

        if (_probeAuthResponseReplayPayloadProvided && !_probeAuthResponseReplayPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeAuthResponseReplayPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeAuthResponseReplayPayloadHexPath,
                _probeAuthResponseReplayPayloadResolvedPath ?? "<unresolved>",
                _probeAuthResponseReplayPayloadParseError ?? "<unknown>");
        }

        if (_probeAuthResponseReplayPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_RESPONSE payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeAuthResponseReplayPayloadResolvedPath ?? _options.ProbeAuthResponseReplayPayloadHexPath,
                _probeAuthResponseReplayPayload.Length);

            if (_probeAuthResponseReplayPatchTimeToNow)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (Time field at payload offset {Offset} is overwritten with current unix time per frame).",
                    AuthResponseReplayTimeFieldOffset);
            }

            if (_probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (Active/AccountExpansionLevel at payload offsets {ActiveOffset}/{AccountOffset} are overwritten from AC account expansion per frame).",
                    AuthResponseReplayActiveExpansionLevelOffset,
                    AuthResponseReplayAccountExpansionLevelOffset);
            }

            if (_probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (AvailableClasses class-matrix expansion triplets are overwritten from AC account expansion per frame).");
            }

            if (_probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (AvailableClasses class-matrix is reduced to classes allowed by runtime AC account expansion).");
            }

            if (_probeAuthResponseReplayPatchCurrentBuildPresent)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (SuccessInfo optional CurrentBuild field is forced present and set to {Build}).",
                    AuthResponseReplayCurrentBuildValue);
            }

            if (_probeAuthResponseReplayPatchWaitInfoPresent)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (top-level WaitInfo optional block is forced present with canonical zero values).");
            }

            if (_probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (VirtualRealmInfo entry RealmAddress is overwritten from runtime realm identity).");
            }

            if (_probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (top-level AuthSuccessInfo.VirtualRealmAddress is overwritten from runtime realm identity).");
            }

            if (_probeAuthResponseReplayBisectionResultOnlyErrorOk)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay structural bisection active (first deferred AUTH_RESPONSE payload is forced to result-only ERROR_OK in replay path).");
            }
        }

        if (_probeAuthResponseReplayCompressedPayloadProvided && !_probeAuthResponseReplayCompressedPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeAuthResponseReplayCompressedPayloadHexPath is invalid ('{ConfiguredValue}'). Compressed replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeAuthResponseReplayCompressedPayloadHexPath,
                _probeAuthResponseReplayCompressedPayloadResolvedPath ?? "<unresolved>",
                _probeAuthResponseReplayCompressedPayloadParseError ?? "<unknown>");
        }

        if (_probeAuthResponseReplayCompressedPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_RESPONSE compressed payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeAuthResponseReplayCompressedPayloadResolvedPath ?? _options.ProbeAuthResponseReplayCompressedPayloadHexPath,
                _probeAuthResponseReplayCompressedPayload.Length);
        }

        if (_probeSetTimeZoneInformationPayloadProvided && !_probeSetTimeZoneInformationPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeSetTimeZoneInformationPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeSetTimeZoneInformationPayloadHexPath,
                _probeSetTimeZoneInformationPayloadResolvedPath ?? "<unresolved>",
                _probeSetTimeZoneInformationPayloadParseError ?? "<unknown>");
        }

        if (_probeSetTimeZoneInformationPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: SET_TIME_ZONE_INFORMATION payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeSetTimeZoneInformationPayloadResolvedPath ?? _options.ProbeSetTimeZoneInformationPayloadHexPath,
                _probeSetTimeZoneInformationPayload.Length);
        }

        if (_probeFeatureSystemStatusGlueScreenPayloadProvided && !_probeFeatureSystemStatusGlueScreenPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeFeatureSystemStatusGlueScreenPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeFeatureSystemStatusGlueScreenPayloadHexPath,
                _probeFeatureSystemStatusGlueScreenPayloadResolvedPath ?? "<unresolved>",
                _probeFeatureSystemStatusGlueScreenPayloadParseError ?? "<unknown>");
        }

        if (_probeFeatureSystemStatusGlueScreenPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: FEATURE_SYSTEM_STATUS_GLUE_SCREEN payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeFeatureSystemStatusGlueScreenPayloadResolvedPath ?? _options.ProbeFeatureSystemStatusGlueScreenPayloadHexPath,
                _probeFeatureSystemStatusGlueScreenPayload.Length);
        }

        if (_probeMirrorVarsPayloadProvided && !_probeMirrorVarsPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeMirrorVarsPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeMirrorVarsPayloadHexPath,
                _probeMirrorVarsPayloadResolvedPath ?? "<unresolved>",
                _probeMirrorVarsPayloadParseError ?? "<unknown>");
        }

        if (_probeMirrorVarsPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: MIRROR_VARS payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeMirrorVarsPayloadResolvedPath ?? _options.ProbeMirrorVarsPayloadHexPath,
                _probeMirrorVarsPayload.Length);
        }

        if (_probeCacheVersionPayloadProvided && !_probeCacheVersionPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeCacheVersionPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeCacheVersionPayloadHexPath,
                _probeCacheVersionPayloadResolvedPath ?? "<unresolved>",
                _probeCacheVersionPayloadParseError ?? "<unknown>");
        }

        if (_probeCacheVersionPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: CACHE_VERSION payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeCacheVersionPayloadResolvedPath ?? _options.ProbeCacheVersionPayloadHexPath,
                _probeCacheVersionPayload.Length);
        }

        if (_probeAvailableHotfixesPayloadProvided && !_probeAvailableHotfixesPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeAvailableHotfixesPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeAvailableHotfixesPayloadHexPath,
                _probeAvailableHotfixesPayloadResolvedPath ?? "<unresolved>",
                _probeAvailableHotfixesPayloadParseError ?? "<unknown>");
        }

        if (_probeAvailableHotfixesPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AVAILABLE_HOTFIXES payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeAvailableHotfixesPayloadResolvedPath ?? _options.ProbeAvailableHotfixesPayloadHexPath,
                _probeAvailableHotfixesPayload.Length);
        }

        if (_probeAccountDataTimesPayloadProvided && !_probeAccountDataTimesPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeAccountDataTimesPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeAccountDataTimesPayloadHexPath,
                _probeAccountDataTimesPayloadResolvedPath ?? "<unresolved>",
                _probeAccountDataTimesPayloadParseError ?? "<unknown>");
        }

        if (_probeAccountDataTimesPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: ACCOUNT_DATA_TIMES payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeAccountDataTimesPayloadResolvedPath ?? _options.ProbeAccountDataTimesPayloadHexPath,
                _probeAccountDataTimesPayload.Length);
        }

        if (_probeTutorialFlagsPayloadProvided && !_probeTutorialFlagsPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeTutorialFlagsPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeTutorialFlagsPayloadHexPath,
                _probeTutorialFlagsPayloadResolvedPath ?? "<unresolved>",
                _probeTutorialFlagsPayloadParseError ?? "<unknown>");
        }

        if (_probeTutorialFlagsPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: TUTORIAL_FLAGS payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeTutorialFlagsPayloadResolvedPath ?? _options.ProbeTutorialFlagsPayloadHexPath,
                _probeTutorialFlagsPayload.Length);
        }

        if (_probeBattleNetConnectionStatusPayloadProvided && !_probeBattleNetConnectionStatusPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeBattleNetConnectionStatusPayloadHexPath is invalid ('{ConfiguredValue}'). Replay disabled. ResolvedPath={ResolvedPath}, Error={Error}",
                _options.ProbeBattleNetConnectionStatusPayloadHexPath,
                _probeBattleNetConnectionStatusPayloadResolvedPath ?? "<unresolved>",
                _probeBattleNetConnectionStatusPayloadParseError ?? "<unknown>");
        }

        if (_probeBattleNetConnectionStatusPayloadValid)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: BATTLE_NET_CONNECTION_STATUS payload replay active (Path={Path}, PayloadBytes={PayloadBytes}).",
                _probeBattleNetConnectionStatusPayloadResolvedPath ?? _options.ProbeBattleNetConnectionStatusPayloadHexPath,
                _probeBattleNetConnectionStatusPayload.Length);
        }

        if (!_bootstrapFlushTriggerModeValid)
        {
            _logger.LogWarning(
                "WorldProxy option BootstrapFlushTriggerSource is invalid ('{ConfiguredValue}'). Falling back to 'ack'.",
                _options.BootstrapFlushTriggerSource);
        }

        if (_probeDropDeferredOpcodes.Count > 0)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: drop deferred post-auth frame opcodes {Opcodes}.",
                string.Join(", ", _probeDropDeferredOpcodes.Select(opcode => $"0x{opcode:X8}")));
        }

        if (_options.ProbeBareAuthResponseOnly)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: bare SMSG_AUTH_RESPONSE mode active (optional post-auth packets are suppressed until CHAR_ENUM).");
        }

        if (_options.ProbeRetailAuthChallengeCountAsPreAckWorldFrame)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_CHALLENGE is routed through RetailWorldPacketCrypt pre-ACK path for counter continuity.");
        }

        if (_options.ProbeRetailAuthSessionCountAsPreAckClientFrame)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: CMSG_AUTH_SESSION is counted via RetailWorldPacketCrypt pre-ACK client path for counter continuity.");
        }

        if (_options.ProbeAuthResponseResultOnly)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_RESPONSE result-only mode active (payload contains only uint32 ResultCode={ResultCode}).",
                _options.ProbeAuthResponseResultOnlyCode);
        }

        if (_options.ProbeAuthResponseMinimalSuccessNoAccountData)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: minimal AUTH_RESPONSE mode active (success=true, has_success_info=false).");
        }

        if (_options.ProbeAuthResponseTwwAccountDataProfile)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: TWW AUTH_RESPONSE account-data profile active (build-66102 envelope candidate).");
        }

        if (_options.ProbeAuthResponseTwwAddResultPrefix)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: TWW AUTH_RESPONSE result-prefix mode active (prepend uint32 result before bit block).");
        }

        if (_options.ProbeAuthResponseForceWaitInfoPresent)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_RESPONSE WaitInfo bit is forced present in non-TWW serializer.");
        }

        if (_options.ProbeAuthResponseForceCurrentBuildPresent)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: AUTH_RESPONSE SuccessInfo CurrentBuild optional field is forced present in non-TWW serializer.");
        }

        if (_options.ProbeAuthResponseTwwClassMatrixRows > 0)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: TWW AUTH_RESPONSE Trinity class-matrix prefix active (Rows={Rows}).",
                _options.ProbeAuthResponseTwwClassMatrixRows);
        }

        if (_options.ProbeAuthResponseTwwUseAcoreExpansionLevels)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: TWW AUTH_RESPONSE top-level expansion fields are sourced from AC payload/account expansion.");
        }

        if (_options.ProbeInsertRetailSequencePreludeBeforeAuthResponse)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: retail sequence prelude mode active (inject 0x{Opcode:X8} before AUTH_RESPONSE, Payload={PayloadHex}).",
                RetailOpcodeSmsgAuthSequencePrelude,
                Convert.ToHexString(_probeRetailSequencePreludePayload));
        }

        if (_options.ProbeInsertRetailSequencePreludeBeforeAuthResponse &&
            _options.ProbeInsertRetailSequencePreludeAfterAuthResponse)
        {
            _logger.LogWarning(
                "WorldProxy probe configuration conflict: both prelude-before and prelude-after are enabled. Prelude-after will be ignored to keep a single prelude frame.");
        }
        else if (_options.ProbeInsertRetailSequencePreludeAfterAuthResponse)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: retail sequence prelude mode active (inject 0x{Opcode:X8} after AUTH_RESPONSE, Payload={PayloadHex}).",
                RetailOpcodeSmsgAuthSequencePrelude,
                Convert.ToHexString(_probeRetailSequencePreludePayload));
        }

        if (_options.ProbeReorderFirstDeferredFrameAfterPrelude)
        {
            if (_options.ProbeInsertRetailSequencePreludeBeforeAuthResponse ||
                !_options.ProbeInsertRetailSequencePreludeAfterAuthResponse)
            {
                _logger.LogWarning(
                    "WorldProxy probe option ProbeReorderFirstDeferredFrameAfterPrelude is enabled but preconditions are not met (requires prelude-after-auth only). Reorder probe is ignored.");
            }
            else
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: deferred bootstrap reorder active (move first deferred frame to slot immediately after prelude 0x{Opcode:X8}).",
                    RetailOpcodeSmsgAuthSequencePrelude);
            }
        }

        if (_bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: deferred post-auth bootstrap flush is triggered by first client post-ACK non-ACK frame.");

            if (_options.BootstrapFlushTriggerFallbackTimeoutMs > 0)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: deferred bootstrap fallback timeout is active ({TimeoutMs}ms). If post-ACK non-ACK trigger is absent, deferred bootstrap is flushed on timeout.",
                    _options.BootstrapFlushTriggerFallbackTimeoutMs);
            }
        }
        else if (_options.BootstrapFlushTriggerFallbackTimeoutMs > 0)
        {
            _logger.LogWarning(
                "WorldProxy option BootstrapFlushTriggerFallbackTimeoutMs is set to {TimeoutMs}ms but BootstrapFlushTriggerSource='{TriggerSource}'. Fallback timeout is ignored.",
                _options.BootstrapFlushTriggerFallbackTimeoutMs,
                _options.BootstrapFlushTriggerSource);
        }

        if (_options.ProbeExplicitBootstrapFlushMarker)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: explicit bootstrap flush marker is active.");
        }

        if (_options.ProbeFeatureSystemStatusGlueScreenTrinitySemantics)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: FEATURE_SYSTEM_STATUS_GLUE_SCREEN Trinity semantics active (Europa optional present + BN v2 service bits enabled).");
        }

        if (_options.ProbeCompressAuthResponseAsSmsgCompressedPacket)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: first post-ACK SMSG_AUTH_RESPONSE is wrapped as SMSG_COMPRESSED_PACKET when payload exceeds Trinity threshold (>0x{Threshold:X}).",
                TrinityCompressionThresholdBytes);

            if (_options.ProbeCompressedAuthResponseForceEnvelope)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: compressed AUTH_RESPONSE envelope is forced even when payload is at/below Trinity compression threshold.");
            }
        }

        if (_options.ProbeCompressedAuthResponseUseRawDeflate)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE payload uses raw deflate stream (no zlib wrapper).");
        }

        if (_options.ProbeCompressedAuthResponseUseStatefulDeflateSyncFlush)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE payload uses stateful raw-deflate stream with sync-flush boundaries.");
        }

        if (_options.ProbeCompressAuthResponseAsSmsgCompressedPacket && _options.ProbeCompressedAuthResponseUseRawDeflate)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE raw-deflate level={RawDeflateLevel} (Trinity parity target: 1).",
                RetailCompressionCodec.NormalizeDeflateLevel(_options.ProbeCompressedAuthResponseRawDeflateLevel));
        }

        if (_options.ProbeCompressedAuthResponseChecksumPayloadOnly)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE uncompressed Adler checksum uses payload-only scope (opcode excluded).");
        }

        if (_options.ProbeCompressAuthResponseAsSmsgCompressedPacket)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE checksum seed=0x{ChecksumSeed:X8}.",
                RetailCompressionCodec.NormalizeChecksumSeed(_options.ProbeCompressedAuthResponseChecksumSeed, TrinityCompressionAdlerSeed));
        }

        if (_options.ProbeCompressedAuthResponseCompressedChecksumIncludeMetadata)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE compressed Adler checksum includes metadata prefix (uncompressed_size + uncompressed_adler).");
        }

        if (_options.EnterEncryptedModeUseGoldenPayload && _options.EnterEncryptedModeGoldenPatchRuntimeSignature)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: ENTER_ENCRYPTED_MODE golden payload will be patched with runtime signature.");
        }

        if (_options.EnterEncryptedModeParityGateEnabled)
        {
            _logger.LogWarning(
                "WorldProxy parity gate enabled for ENTER_ENCRYPTED_MODE payload (FixturePath={FixturePath}).",
                string.IsNullOrWhiteSpace(_options.EnterEncryptedModeParityFixturePath)
                    ? "<auto:docs/handshake/runlogs/enter_encrypted_mode.golden*.hex|json>"
                    : _options.EnterEncryptedModeParityFixturePath);

            if (_options.EnterEncryptedModeUseGoldenPayload && _options.EnterEncryptedModeGoldenPatchRuntimeSignature)
            {
                _logger.LogWarning(
                    "WorldProxy parity gate in runtime-signature mode: ENTER_ENCRYPTED_MODE signature bytes are excluded from fixture diff; gate enforces structural parity only.");
            }
            else if (!_options.EnterEncryptedModeUseGoldenPayload)
            {
                _logger.LogWarning(
                    "WorldProxy parity gate in runtime-generated mode: ENTER_ENCRYPTED_MODE signature bytes are excluded from fixture diff; gate enforces structural parity only.");
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeFirstDeferredFrameParityFixturePath))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: first deferred frame parity fixture configured (FixturePath={FixturePath}).",
                _options.ProbeFirstDeferredFrameParityFixturePath);
        }

        if (_options.RetailWorldPacketCryptServerInitialCounter != 0)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt server initial counter override active ({Counter}).",
                _options.RetailWorldPacketCryptServerInitialCounter);
        }

        if (_options.RetailWorldPacketCryptUseSizeAsAad)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt uses plaintext size field as AES-GCM AAD (AadSizeBytes={AadSizeBytes}).",
                _options.RetailWorldPacketCryptAadSizeBytes);
        }

        if (_options.RetailWorldPacketCryptUseEmptyAad)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt uses empty AAD (zero-length associated data).");
        }

        if (!string.Equals(_options.RetailWorldPacketCryptNonceLayout, "counter_le_magic_le", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt nonce layout override active ({NonceLayout}).",
                _options.RetailWorldPacketCryptNonceLayout);
        }

        if (!string.Equals(_options.RetailWorldPacketCryptServerNonceMagic, "srvr", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt server nonce magic override active ({ServerNonceMagic}).",
                _options.RetailWorldPacketCryptServerNonceMagic);
        }

        if (!string.Equals(_options.RetailWorldPacketCryptClientNonceMagic, "clnt", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt client nonce magic override active ({ClientNonceMagic}).",
                _options.RetailWorldPacketCryptClientNonceMagic);
        }

        if (_options.ProbeAuthResponseFuzzerEnabled)
        {
            if (!_authResponseFuzzPlanRecognized)
            {
                _logger.LogWarning(
                    "WorldProxy fuzzer enabled with unknown plan '{Plan}'. Mutation is disabled for this run.",
                    _options.ProbeAuthResponseFuzzerPlan);
            }
            else
            {
                _logger.LogWarning(
                    "WorldProxy fuzzer active: Plan={Plan}, Iteration={Iteration}, Mutation={Mutation}, LeadingZeroBits={LeadingZeroBits}, AccountDataPermutationVariant={AccountDataPermutationVariant}, OpcodeOverride={OpcodeOverride}, UseShortRealmId={UseShortRealmId}, SwapExpansionAndBillingFlags={SwapExpansionAndBillingFlags}, InsertPaddingU32AfterBitBlock={InsertPaddingU32AfterBitBlock}",
                    _authResponseFuzzMutation.Plan,
                    _authResponseFuzzMutation.Iteration,
                    _authResponseFuzzMutation.MutationLabel,
                    _authResponseFuzzMutation.LeadingZeroBits,
                    _authResponseFuzzMutation.AccountDataPermutationVariant,
                    _authResponseFuzzMutation.OpcodeOverride is uint fuzzOpcode
                        ? $"0x{fuzzOpcode:X8}"
                        : "<none>",
                    _authResponseFuzzMutation.UseShortRealmId,
                    _authResponseFuzzMutation.SwapExpansionAndBillingFlags,
                    _authResponseFuzzMutation.InsertPaddingU32AfterBitBlock);
            }
        }

        _logger.LogInformation(
            "WorldProxy started on {ListenAddress}:{ListenPort} -> {UpstreamAddress}:{UpstreamPort} (Backlog={Backlog}, EnterEncryptedModeAckTimeoutMs={AckTimeoutMs}, EnterEncryptedModeAckGateEnabled={AckGateEnabled}, EffectiveAckGate={EffectiveAckGate}, EffectiveAckGateSource={EffectiveAckGateSource}, SuppressPostAuthBootstrapForProbe={SuppressBootstrap}, ProbeAuthResponseTwwAccountDataProfile={ProbeAuthResponseTwwAccountDataProfile}, ProbeAuthResponseTwwAddResultPrefix={ProbeAuthResponseTwwAddResultPrefix}, ProbeAuthResponseAvailableClassesCardinality={ProbeAuthResponseAvailableClassesCardinality}, ProbeAuthResponseTwwClassMatrixRows={ProbeAuthResponseTwwClassMatrixRows}, ProbeAuthResponseTwwUseAcoreExpansionLevels={ProbeAuthResponseTwwUseAcoreExpansionLevels}, ProbeInsertRetailSequencePreludeBeforeAuthResponse={ProbeInsertRetailSequencePreludeBeforeAuthResponse}, ProbeInsertRetailSequencePreludeAfterAuthResponse={ProbeInsertRetailSequencePreludeAfterAuthResponse}, ProbeReorderFirstDeferredFrameAfterPrelude={ProbeReorderFirstDeferredFrameAfterPrelude}, ProbeRetailSequencePreludePayloadHex={ProbeRetailSequencePreludePayloadHex}, ProbeAuthResponseOpcode=0x{ProbeAuthResponseOpcode:X8}, RetailAuthChallengeRandomizeDosBlock={RandomizeDosBlock}, EnterEncryptedModeSignatureFirst={SignatureFirst}, EnterEncryptedModeRegionGroup={RegionGroup}, EnterEncryptedModeIncludeRegionGroup={IncludeRegionGroup}, EnterEncryptedModeEnabled={Enabled}, EnterEncryptedModeEnabledAsByte={EnabledAsByte}, EnterEncryptedModeOpcode=0x{EnterEncryptedOpcode:X8}, EnterEncryptedModePreferBnetKeyData={PreferBnetKeyData}, EnableRetailWorldPacketCryptOnAck={EnableRetailWorldPacketCryptOnAck}, ForwardAcoreWardenAsRetailWarden3Data={ForwardAcoreWardenAsRetailWarden3Data}, ForwardAcoreAddonInfoAsRetailAddonListRequest={ForwardAcoreAddonInfoAsRetailAddonListRequest}, ForwardAcoreTutorialFlagsAsRetailTutorialFlags={ForwardAcoreTutorialFlagsAsRetailTutorialFlags}, RetailWorldPacketCryptServerInitialCounter={RetailWorldPacketCryptServerInitialCounter}, RetailWorldPacketCryptUseSizeAsAad={RetailWorldPacketCryptUseSizeAsAad}, RetailWorldPacketCryptAadSizeBytes={RetailWorldPacketCryptAadSizeBytes}, RetailWorldPacketCryptUseEmptyAad={RetailWorldPacketCryptUseEmptyAad}, RetailWorldPacketCryptNonceLayout={RetailWorldPacketCryptNonceLayout}, RetailWorldPacketCryptServerNonceMagic={RetailWorldPacketCryptServerNonceMagic}, RetailWorldPacketCryptClientNonceMagic={RetailWorldPacketCryptClientNonceMagic}, ControlledUnlockEmptyCharEnumEnabled={ControlledUnlockEmptyCharEnumEnabled}, GlueSyntheticCharEnumKickMinIntervalMs={GlueSyntheticCharEnumKickMinIntervalMs}, ReconnectCooldownMs={ReconnectCooldownMs}, EnterEncryptedModeUseGoldenPayload={UseGoldenPayload}, EnterEncryptedModeGoldenMetadataPath={GoldenMetadataPath}, EnterEncryptedModeGoldenPatchRuntimeSignature={GoldenPatchRuntimeSignature}, EnterEncryptedModeParityGateEnabled={EnterEncryptedModeParityGateEnabled}, EnterEncryptedModeParityFixturePath={EnterEncryptedModeParityFixturePath}, ExposeRetailWorldEncryptKeyInProof={ExposeRetailWorldEncryptKeyInProof}, AuthAccountIdFallback={AuthAccountIdFallback}, EnableProofPack={EnableProofPack}, EnableHandshakeLabReport={EnableHandshakeLabReport}, ProofPackRootPath={ProofPackRootPath}, ScenarioId={ScenarioId}, PassThreshold={PassThreshold}, AckPolicy={AckPolicy}, AckPolicyDecisionPath={AckPolicyDecisionPath}, DeterministicReplayEnabled={DeterministicReplayEnabled}, HypothesisId={HypothesisId}, SingleChangedVariable={SingleChangedVariable}, ExpectedObservable={ExpectedObservable}, NextIsolationVariable={NextIsolationVariable}, FailureClassTarget={FailureClassTarget}, ActiveLayer={ActiveLayer}, ParityAxis={ParityAxis}, StrictStageEnforcement={StrictStageEnforcement})",
            bindAddress,
            _options.ListenPort,
            _options.UpstreamAddress,
            _options.UpstreamPort,
            _options.Backlog,
            _options.EnterEncryptedModeAckTimeoutMs,
            _options.EnterEncryptedModeAckGateEnabled,
            resolvedAckGate,
            ackGateSource,
            _options.SuppressPostAuthBootstrapForProbe,
            _options.ProbeAuthResponseTwwAccountDataProfile,
            _options.ProbeAuthResponseTwwAddResultPrefix,
            _options.ProbeAuthResponseAvailableClassesCardinality,
            _options.ProbeAuthResponseTwwClassMatrixRows,
            _options.ProbeAuthResponseTwwUseAcoreExpansionLevels,
            _options.ProbeInsertRetailSequencePreludeBeforeAuthResponse,
            _options.ProbeInsertRetailSequencePreludeAfterAuthResponse,
            _options.ProbeReorderFirstDeferredFrameAfterPrelude,
            Convert.ToHexString(_probeRetailSequencePreludePayload),
            _probeAuthResponseOpcode,
            _options.RetailAuthChallengeRandomizeDosBlock,
            _options.EnterEncryptedModeSignatureFirst,
            _options.EnterEncryptedModeRegionGroup,
            _options.EnterEncryptedModeIncludeRegionGroup,
            _options.EnterEncryptedModeEnabled,
            _options.EnterEncryptedModeEnabledAsByte,
            _enterEncryptedModeOpcode,
            _options.EnterEncryptedModePreferBnetKeyData,
            _options.EnableRetailWorldPacketCryptOnAck,
            _options.ForwardAcoreWardenAsRetailWarden3Data,
            _options.ForwardAcoreAddonInfoAsRetailAddonListRequest,
            _options.ForwardAcoreTutorialFlagsAsRetailTutorialFlags,
            _options.RetailWorldPacketCryptServerInitialCounter,
            _options.RetailWorldPacketCryptUseSizeAsAad,
            _options.RetailWorldPacketCryptAadSizeBytes,
            _options.RetailWorldPacketCryptUseEmptyAad,
            _options.RetailWorldPacketCryptNonceLayout,
            _options.RetailWorldPacketCryptServerNonceMagic,
            _options.RetailWorldPacketCryptClientNonceMagic,
            _options.ControlledUnlockEmptyCharEnumEnabled,
            _options.GlueSyntheticCharEnumKickMinIntervalMs,
            _options.ReconnectCooldownMs,
            _options.EnterEncryptedModeUseGoldenPayload,
            _options.EnterEncryptedModeGoldenMetadataPath,
            _options.EnterEncryptedModeGoldenPatchRuntimeSignature,
            _options.EnterEncryptedModeParityGateEnabled,
            _options.EnterEncryptedModeParityFixturePath,
            _options.ExposeRetailWorldEncryptKeyInProof,
            _options.AuthAccountIdFallback,
            _options.EnableProofPack,
            _options.EnableHandshakeLabReport,
            _options.ProofPackRootPath,
            _protocolOptions.ScenarioId,
            _protocolOptions.PassThreshold,
            _protocolOptions.AckPolicy,
            _protocolOptions.AckPolicyDecisionPath,
            _protocolOptions.DeterministicReplayEnabled,
            _protocolOptions.HypothesisId,
            _protocolOptions.SingleChangedVariable,
            _protocolOptions.ExpectedObservable,
            _protocolOptions.NextIsolationVariable,
            _protocolOptions.FailureClassTarget,
            _protocolOptions.ActiveLayer,
            _protocolOptions.ParityAxis,
            _protocolOptions.StrictStageEnforcement);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                uint connectionId = unchecked((uint)Interlocked.Increment(ref _connectionSequence));
                Task connectionTask = HandleConnectionAsync(client, connectionId, stoppingToken);

                lock (_activeConnectionsLock)
                {
                    _activeConnections.Add(connectionTask);
                }

                _ = connectionTask.ContinueWith(
                    _ =>
                    {
                        lock (_activeConnectionsLock)
                        {
                            _activeConnections.Remove(connectionTask);
                        }
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        finally
        {
            _listener.Stop();

            Task[] pending;
            lock (_activeConnectionsLock)
            {
                pending = _activeConnections.ToArray();
            }

            if (pending.Length > 0)
            {
                await Task.WhenAll(pending).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleConnectionAsync(TcpClient downstreamClient, uint connectionId, CancellationToken serverToken)
    {
        using (downstreamClient)
        {
            string downstreamRemote = downstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            string downstreamKey = ResolveDownstreamKey(downstreamClient.Client.RemoteEndPoint, downstreamRemote);
            downstreamClient.NoDelay = true;
            DateTimeOffset connectionOpenedAt = DateTimeOffset.UtcNow;

            _logger.LogInformation(
                "World connection opened: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}",
                connectionId,
                downstreamRemote);

            if (TryGetReconnectCooldownRemainingMs(downstreamKey, out int reconnectCooldownRemainingMs))
            {
                _logger.LogInformation(
                    "[WorldProxy][ANTISPAM] Reconnect blocked by cooldown. ConnectionId={ConnectionId}, DownstreamKey={DownstreamKey}, RemainingMs={RemainingMs}, CooldownMs={CooldownMs}",
                    connectionId,
                    downstreamKey,
                    reconnectCooldownRemainingMs,
                    _options.ReconnectCooldownMs);
                return;
            }

            using var upstreamClient = new TcpClient(AddressFamily.InterNetwork);
            upstreamClient.NoDelay = true;

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                connectCts.CancelAfter(_options.UpstreamConnectTimeoutMs);
                await upstreamClient.ConnectAsync(_options.UpstreamAddress, _options.UpstreamPort, connectCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException)
            {
                _logger.LogWarning(
                    ex,
                    "Upstream connect failed: ConnectionId={ConnectionId}, Upstream={UpstreamAddress}:{UpstreamPort}",
                    connectionId,
                    _options.UpstreamAddress,
                    _options.UpstreamPort);
                return;
            }

            string upstreamRemote = upstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            _logger.LogInformation(
                "World upstream connected: ConnectionId={ConnectionId}, Upstream={UpstreamRemote}",
                connectionId,
                upstreamRemote);

            await using NetworkStream downstreamStream = downstreamClient.GetStream();
            await using NetworkStream upstreamStream = upstreamClient.GetStream();

            if (_options.EnableRetailConnectionInitializer)
            {
                bool initialized = await TryPerformRetailConnectionInitializerAsync(connectionId, downstreamStream, relayToken: serverToken).ConfigureAwait(false);
                if (!initialized)
                {
                    _logger.LogWarning(
                        "World initializer failed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}. Closing connection.",
                        connectionId,
                        downstreamRemote);
                    return;
                }
            }

            var downstreamReader = PipeReader.Create(
                downstreamStream,
                new StreamPipeReaderOptions(
                    bufferSize: _options.ReaderBufferSize,
                    minimumReadSize: _options.MinimumReadSize,
                    leaveOpen: true));

            var downstreamWriter = PipeWriter.Create(downstreamStream, new StreamPipeWriterOptions(leaveOpen: true));
            var upstreamReader = PipeReader.Create(
                upstreamStream,
                new StreamPipeReaderOptions(
                    bufferSize: _options.ReaderBufferSize,
                    minimumReadSize: _options.MinimumReadSize,
                    leaveOpen: true));

            var upstreamWriter = PipeWriter.Create(upstreamStream, new StreamPipeWriterOptions(leaveOpen: true));

            using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
            var bridgeState = new WorldProxyBridgeState(
                logger: _logger,
                retailWorldPacketCryptServerInitialCounter: (ulong)_options.RetailWorldPacketCryptServerInitialCounter,
                retailWorldPacketCryptUseSizeAsAad: _options.RetailWorldPacketCryptUseSizeAsAad,
                retailWorldPacketCryptAadSizeBytes: _options.RetailWorldPacketCryptAadSizeBytes,
                retailWorldPacketCryptUseEmptyAad: _options.RetailWorldPacketCryptUseEmptyAad,
                retailWorldPacketCryptNonceLayout: _options.RetailWorldPacketCryptNonceLayout,
                retailWorldPacketCryptServerNonceMagic: _options.RetailWorldPacketCryptServerNonceMagic,
                retailWorldPacketCryptClientNonceMagic: _options.RetailWorldPacketCryptClientNonceMagic);
            bridgeState.SetConnectionOpenedAt(connectionOpenedAt);
            bridgeState.SetBaseline(
                new HandshakeBaseline(
                    ScenarioId: _protocolOptions.ScenarioId,
                    ClientBuild: _protocolOptions.ClientBuild,
                    RealmConfig: _protocolOptions.RealmConfig,
                    AccountIdentity: _protocolOptions.AccountIdentity,
                    AckPolicy: _protocolOptions.AckPolicy,
                    PassThreshold: _protocolOptions.PassThreshold,
                    DeterministicReplayEnabled: _protocolOptions.DeterministicReplayEnabled,
                    FailureClassTarget: _protocolOptions.FailureClassTarget,
                    ActiveLayer: _protocolOptions.ActiveLayer,
                    ParityAxis: _protocolOptions.ParityAxis,
                    BaselineTimestampUtc: DateTimeOffset.UtcNow.ToString("O")));

            Task<long> downstreamToUpstream = ProxyStreamAsync(
                connectionId,
                "client->world",
                downstreamReader,
                upstreamWriter,
                downstreamKey,
                bridgeState,
                relayCts.Token);

            Task<long> upstreamToDownstream = ProxyStreamAsync(
                connectionId,
                "world->client",
                upstreamReader,
                downstreamWriter,
                downstreamKey,
                bridgeState,
                relayCts.Token);

            long transferredClientToWorld = 0;
            long transferredWorldToClient = 0;

            try
            {
                Task completed = await Task.WhenAny(downstreamToUpstream, upstreamToDownstream).ConfigureAwait(false);
                string firstCompletedDirection = ReferenceEquals(completed, downstreamToUpstream)
                    ? "client->world"
                    : "world->client";
                string firstCompletedStatus = completed.IsFaulted
                    ? "faulted"
                    : completed.IsCanceled
                        ? "canceled"
                        : "completed";
                string firstCompletedError = completed.Exception?.GetBaseException().Message ?? "<none>";
                _logger.LogInformation(
                    "[WorldProxy][L4] First relay side finished. ConnectionId={ConnectionId}, Direction={Direction}, Status={Status}, Error={Error}",
                    connectionId,
                    firstCompletedDirection,
                    firstCompletedStatus,
                    firstCompletedError);
                relayCts.Cancel();

                try
                {
                    await completed.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected when one side closes first.
                }

                try
                {
                    transferredClientToWorld = await downstreamToUpstream.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ignore cancellation, this is normal on half-close.
                }

                try
                {
                    transferredWorldToClient = await upstreamToDownstream.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ignore cancellation, this is normal on half-close.
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Proxy loop error: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}",
                    connectionId,
                    downstreamRemote,
                    upstreamRemote);
            }
            finally
            {
                await CompletePipeSafelyAsync(downstreamReader).ConfigureAwait(false);
                await CompletePipeSafelyAsync(downstreamWriter).ConfigureAwait(false);
                await CompletePipeSafelyAsync(upstreamReader).ConfigureAwait(false);
                await CompletePipeSafelyAsync(upstreamWriter).ConfigureAwait(false);
            }

            _logger.LogInformation(
                "World connection closed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}, BytesClientToWorld={BytesClientToWorld}, BytesWorldToClient={BytesWorldToClient}",
                connectionId,
                downstreamRemote,
                upstreamRemote,
                transferredClientToWorld,
                transferredWorldToClient);

            if (_options.EnableHandshakeLabReport)
            {
                try
                {
                    HandshakeLabReport report = HandshakeLabReport.Create(
                        connectionId,
                        _options,
                        _protocolOptions,
                        bridgeState,
                        connectionOpenedAt,
                        DateTimeOffset.UtcNow,
                        transferredClientToWorld,
                        transferredWorldToClient);

                    string reportPath = HandshakeDiagnosticsWriters.WriteHandshakeLabReport(
                        report,
                        WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options));
                    HandshakeDiagnosticsWriters.AppendNegativeEvidenceMatrixRow(
                        reportPath,
                        report,
                        WorldGatewayPathResolver.ResolveProofPackRoot(_options));
                    _logger.LogInformation(
                        "[WorldProxy][HANDSHAKE-LAB] Report written. ConnectionId={ConnectionId}, Path={Path}",
                        connectionId,
                        reportPath);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                {
                    _logger.LogWarning(
                        ex,
                        "[WorldProxy][HANDSHAKE-LAB] Failed to write report. ConnectionId={ConnectionId}",
                        connectionId);
                }
            }
        }
    }

    private static string ResolveDownstreamKey(EndPoint? remoteEndPoint, string fallbackRemote)
    {
        if (remoteEndPoint is IPEndPoint ipEndpoint)
        {
            return ipEndpoint.Address.ToString();
        }

        return string.IsNullOrWhiteSpace(fallbackRemote) ? "unknown" : fallbackRemote;
    }

    private bool TryGetReconnectCooldownRemainingMs(string downstreamKey, out int remainingMs)
    {
        remainingMs = 0;

        int cooldownMs = _options.ReconnectCooldownMs;
        if (cooldownMs <= 0 || string.IsNullOrWhiteSpace(downstreamKey))
        {
            return false;
        }

        long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (!_reconnectCooldownUntilByKey.TryGetValue(downstreamKey, out long cooldownUntilUnixMs))
        {
            return false;
        }

        long deltaMs = cooldownUntilUnixMs - nowUnixMs;
        if (deltaMs <= 0)
        {
            _reconnectCooldownUntilByKey.TryRemove(downstreamKey, out _);
            return false;
        }

        remainingMs = deltaMs > int.MaxValue ? int.MaxValue : (int)deltaMs;
        return true;
    }

    private void ArmReconnectCooldown(string downstreamKey, string source, uint? reason = null)
    {
        int cooldownMs = _options.ReconnectCooldownMs;
        if (cooldownMs <= 0 || string.IsNullOrWhiteSpace(downstreamKey))
        {
            return;
        }

        long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        long cooldownUntilUnixMs = checked(nowUnixMs + cooldownMs);
        _reconnectCooldownUntilByKey.AddOrUpdate(
            downstreamKey,
            cooldownUntilUnixMs,
            (_, existing) => Math.Max(existing, cooldownUntilUnixMs));

        _logger.LogInformation(
            "[WorldProxy][ANTISPAM] Reconnect cooldown armed. DownstreamKey={DownstreamKey}, CooldownMs={CooldownMs}, Source={Source}, Reason={Reason}, UntilUnixMs={UntilUnixMs}",
            downstreamKey,
            cooldownMs,
            source,
            reason.HasValue ? reason.Value.ToString(CultureInfo.InvariantCulture) : "<none>",
            cooldownUntilUnixMs);
    }

    private void ValidateProtocolExperimentContractOrThrow()
    {
        if (string.IsNullOrWhiteSpace(_protocolOptions.HypothesisId) ||
            string.IsNullOrWhiteSpace(_protocolOptions.SingleChangedVariable) ||
            string.IsNullOrWhiteSpace(_protocolOptions.ExpectedObservable) ||
            string.IsNullOrWhiteSpace(_protocolOptions.NextIsolationVariable))
        {
            throw new InvalidOperationException(
                "ProtocolEngineering experiment contract is incomplete. Set HypothesisId, SingleChangedVariable, ExpectedObservable, and NextIsolationVariable before running.");
        }

        string matrixPath = Path.Combine(WorldGatewayPathResolver.ResolveProofPackRoot(_options), "matrix", "negative_evidence.csv");
        if (!File.Exists(matrixPath))
        {
            return;
        }

        if (MatrixPolicyGuard.TryFindRejectedChangeSet(matrixPath, _protocolOptions.SingleChangedVariable, out string? rejectedHypothesis))
        {
            throw new InvalidOperationException(
                $"Rejected change set replay is blocked by matrix policy. SingleChangedVariable='{_protocolOptions.SingleChangedVariable}', RejectedHypothesis='{rejectedHypothesis ?? "<unknown>"}', Matrix='{matrixPath}'.");
        }
    }

    private async Task<long> ProxyStreamAsync(
        uint connectionId,
        string direction,
        PipeReader reader,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        bool firstChunkDumped = false;
        bool firstAcoreChallengeBridged = false;
        bool firstRetailAuthSessionBridged = false;
        bool firstPostAuthDumpedClient = false;
        bool firstPostAuthDumpedServer = false;
        int acServerFramesLogged = 0;
        RetailPostAuthClientTranslator? retailPostAuthClientTranslator = null;
        AcorePostAuthServerTranslator? acorePostAuthServerTranslator = null;
        bool waitForEnterEncryptedAckGate = ResolveEffectiveAckGate(out _);

        while (!cancellationToken.IsCancellationRequested)
        {
            ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = readResult.Buffer;

            if (!buffer.IsEmpty)
            {
                if (_options.EnableFirstPacketDump && !firstChunkDumped)
                {
                    firstChunkDumped = true;
                    int maxBytes = _options.FirstPacketDumpBytes <= 0 ? DefaultDumpBytes : _options.FirstPacketDumpBytes;
                    _logger.LogInformation(
                        "[WorldProxy][DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, maxBytes));

                    if (RetailFrameCodec.TryDecodeFirstHeader(buffer, out DumpHeaderDecode decode))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][DUMP-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, FrameBytes={FrameBytes}, SizeBE={SizeBE}, SizeLE={SizeLE}, OpcodeLE=0x{OpcodeLE:X4}, OpcodeBE=0x{OpcodeBE:X4}, SizeBEMatches={SizeBEMatches}",
                            connectionId,
                            direction,
                            buffer.Length,
                            decode.SizeBE,
                            decode.SizeLE,
                            decode.OpcodeLE,
                            decode.OpcodeBE,
                            decode.SizeBEMatches);

                        if (direction == "world->client" &&
                            decode.OpcodeLE == AcoreOpcodeAuthChallenge &&
                            TryDecodeAzerothAuthChallenge(buffer, out AcoreAuthChallengeDump challenge))
                        {
                            bridgeState.SetAcoreAuthSeed(challenge.AuthSeed);
                            bridgeState.SetAcoreServerChallenge(challenge.NewSeed);

                            _logger.LogInformation(
                                "[WorldProxy][DUMP-AC-AUTH-CHALLENGE] ConnectionId={ConnectionId}, DosChallenge={DosChallenge}, AuthSeed=0x{AuthSeed:X8}, NewSeed={NewSeedHex}",
                                connectionId,
                                challenge.DosChallenge,
                                challenge.AuthSeed,
                                challenge.NewSeedHex);
                        }
                    }
                }

                if (direction == "client->world" &&
                    retailPostAuthClientTranslator is null &&
                    bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt sendCrypt))
                {
                    retailPostAuthClientTranslator = new RetailPostAuthClientTranslator(
                        sendCrypt,
                        bridgeState,
                        strictStageEnforcement: _protocolOptions.StrictStageEnforcement,
                        onLogDisconnect: reason =>
                        {
                            bridgeState.SetLogDisconnectReason(reason);
                            ArmReconnectCooldown(
                                downstreamKey,
                                source: "cmsg_log_disconnect",
                                reason: reason);
                            bridgeState.MarkClientRequestedDisconnect();
                            _logger.LogInformation(
                                "[WorldProxy][MAP] Retail CMSG_LOG_DISCONNECT received. ConnectionId={ConnectionId}, Reason={Reason}",
                                connectionId,
                                reason);
                        },
                        onEnumCharactersRequest: () =>
                        {
                            if (!bridgeState.TryTransitionStage(
                                    BridgeStage.CHAR_ENUM_REQUESTED,
                                    "Retail CMSG_ENUM_CHARACTERS forwarded."))
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][STATE] CHAR_ENUM_REQUESTED transition rejected. ConnectionId={ConnectionId}, Stage={Stage}",
                                    connectionId,
                                    bridgeState.CurrentStage);
                            }
                        },
                        onEnterEncryptedModeAck: () =>
                        {
                            bool signaled = bridgeState.SignalEnterEncryptedAck();
                            bridgeState.MarkEnterEncryptedAckObserved();
                            if (bridgeState.CurrentStage < BridgeStage.BOOTSTRAP_FLUSHED)
                            {
                                bridgeState.TryTransitionStage(
                                    BridgeStage.WORLD_CRYPT_ACTIVE,
                                    "Retail CMSG_ENTER_ENCRYPTED_MODE_ACK observed.");
                            }

                            if (_options.EnableRetailWorldPacketCryptOnAck)
                            {
                                if (bridgeState.TryEnableRetailWorldCrypt(out string? enableError))
                                {
                                    _logger.LogInformation(
                                        "[WorldProxy][CRYPT] Retail world packet crypt enabled on ACK. ConnectionId={ConnectionId}",
                                        connectionId);
                                }
                                else
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][CRYPT] Failed to enable Retail world packet crypt on ACK. ConnectionId={ConnectionId}, Error={Error}",
                                        connectionId,
                                        enableError ?? "<unknown>");
                                }
                            }
                            else
                            {
                                _logger.LogInformation(
                                    "[WorldProxy][CRYPT] Retail world packet crypt-on-ACK disabled by config. ConnectionId={ConnectionId}",
                                    connectionId);
                            }

                            _logger.LogInformation(
                                "[WorldProxy][MAP] Retail CMSG_ENTER_ENCRYPTED_MODE_ACK received. ConnectionId={ConnectionId}, Signaled={Signaled}, Awaiting={Awaiting}",
                                connectionId,
                                signaled,
                                bridgeState.IsAwaitingEnterEncryptedAck);
                        },
                        onPostAckNonAckClientFrame: opcode =>
                        {
                            bool signaled = bridgeState.RegisterPostAckNonAckBootstrapTrigger(opcode);
                            if (signaled)
                            {
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Post-ACK non-ACK client frame observed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}",
                                    connectionId,
                                    opcode);
                            }
                        },
                        glueSyntheticCharEnumKickMinIntervalMs: _options.GlueSyntheticCharEnumKickMinIntervalMs,
                        onGlueSyntheticKickSuppressed: (opcode, waitMs) =>
                        {
                            _logger.LogInformation(
                                "[WorldProxy][GLUE] Synthetic CHAR_ENUM kick throttled. ConnectionId={ConnectionId}, TriggerOpcode=0x{Opcode:X8}, WaitMs={WaitMs}",
                                connectionId,
                                opcode,
                                waitMs);
                        });
                    _logger.LogInformation(
                        "[WorldProxy][MAP] Retail->AC post-auth translator enabled. ConnectionId={ConnectionId}",
                        connectionId);
                }

                if (direction == "world->client" &&
                    acorePostAuthServerTranslator is null &&
                    bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt recvCrypt))
                {
                    acorePostAuthServerTranslator = new AcorePostAuthServerTranslator(
                        recvCrypt,
                        bridgeState,
                        strictStageEnforcement: _protocolOptions.StrictStageEnforcement,
                        waitForEnterEncryptedAckGate: waitForEnterEncryptedAckGate,
                        suppressPostAuthBootstrapForProbe: _options.SuppressPostAuthBootstrapForProbe,
                        probeBareAuthResponseOnly: _options.ProbeBareAuthResponseOnly,
                        probeAuthResponseResultOnly: _options.ProbeAuthResponseResultOnly,
                        probeAuthResponseResultOnlyCode: (uint)Math.Clamp(_options.ProbeAuthResponseResultOnlyCode, 0L, uint.MaxValue),
                        probeAuthResponseMinimalSuccessNoAccountData: _options.ProbeAuthResponseMinimalSuccessNoAccountData,
                        probeAuthResponseTwwAccountDataProfile: _options.ProbeAuthResponseTwwAccountDataProfile,
                        probeAuthResponseTwwAddResultPrefix: _options.ProbeAuthResponseTwwAddResultPrefix,
                        probeAuthResponseForceWaitInfoPresent: _options.ProbeAuthResponseForceWaitInfoPresent,
                        probeAuthResponseForceCurrentBuildPresent: _options.ProbeAuthResponseForceCurrentBuildPresent,
                        probeAuthResponseAvailableClassesCardinality: _options.ProbeAuthResponseAvailableClassesCardinality,
                        probeAuthResponseTwwClassMatrixRows: _options.ProbeAuthResponseTwwClassMatrixRows,
                        probeAuthResponseTwwUseAcoreExpansionLevels: _options.ProbeAuthResponseTwwUseAcoreExpansionLevels,
                        probeInsertRetailSequencePreludeBeforeAuthResponse: _options.ProbeInsertRetailSequencePreludeBeforeAuthResponse,
                        probeInsertRetailSequencePreludeAfterAuthResponse: _options.ProbeInsertRetailSequencePreludeAfterAuthResponse,
                        probeReorderFirstDeferredFrameAfterPrelude: _options.ProbeReorderFirstDeferredFrameAfterPrelude,
                        probeFeatureSystemStatusGlueScreenTrinitySemantics: _options.ProbeFeatureSystemStatusGlueScreenTrinitySemantics,
                        probeCompressAuthResponseAsSmsgCompressedPacket: _options.ProbeCompressAuthResponseAsSmsgCompressedPacket,
                        probeCompressedAuthResponseForceEnvelope: _options.ProbeCompressedAuthResponseForceEnvelope,
                        probeCompressedAuthResponseUseRawDeflate: _options.ProbeCompressedAuthResponseUseRawDeflate,
                        probeCompressedAuthResponseUseStatefulDeflateSyncFlush: _options.ProbeCompressedAuthResponseUseStatefulDeflateSyncFlush,
                        probeCompressedAuthResponseRawDeflateLevel: _options.ProbeCompressedAuthResponseRawDeflateLevel,
                        probeCompressedAuthResponseChecksumPayloadOnly: _options.ProbeCompressedAuthResponseChecksumPayloadOnly,
                        probeCompressedAuthResponseChecksumSeed: _options.ProbeCompressedAuthResponseChecksumSeed,
                        probeCompressedAuthResponseCompressedChecksumIncludeMetadata: _options.ProbeCompressedAuthResponseCompressedChecksumIncludeMetadata,
                        probeRetailSequencePreludePayload: _probeRetailSequencePreludePayload,
                        authResponseFuzzMutation: _authResponseFuzzMutation,
                        probeAuthResponseOpcode: _probeAuthResponseOpcode,
                        probeAuthResponseReplayPayload: _probeAuthResponseReplayPayload,
                        probeAuthResponseReplayCompressedPayload: _probeAuthResponseReplayCompressedPayload,
                        probeAuthResponseReplayPatchTimeToNow: _probeAuthResponseReplayPatchTimeToNow,
                        probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount: _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount,
                        probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount: _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount,
                        probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset: _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset,
                        probeAuthResponseReplayPatchCurrentBuildPresent: _probeAuthResponseReplayPatchCurrentBuildPresent,
                        probeAuthResponseReplayPatchWaitInfoPresent: _probeAuthResponseReplayPatchWaitInfoPresent,
                        probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm: _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm,
                        probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm: _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm,
                        probeAuthResponseReplayBisectionResultOnlyErrorOk: _probeAuthResponseReplayBisectionResultOnlyErrorOk,
                        probeSetTimeZoneInformationPayload: _probeSetTimeZoneInformationPayload,
                        probeFeatureSystemStatusGlueScreenPayload: _probeFeatureSystemStatusGlueScreenPayload,
                        probeMirrorVarsPayload: _probeMirrorVarsPayload,
                        probeCacheVersionPayload: _probeCacheVersionPayload,
                        probeAvailableHotfixesPayload: _probeAvailableHotfixesPayload,
                        probeAccountDataTimesPayload: _probeAccountDataTimesPayload,
                        probeTutorialFlagsPayload: _probeTutorialFlagsPayload,
                        probeBattleNetConnectionStatusPayload: _probeBattleNetConnectionStatusPayload,
                        acoreRealmId: _options.AcoreRealmId,
                        controlledUnlockEmptyCharEnumEnabled: _options.ControlledUnlockEmptyCharEnumEnabled,
                        forwardAcoreWardenAsRetailWarden3Data: _options.ForwardAcoreWardenAsRetailWarden3Data,
                        forwardAcoreAddonInfoAsRetailAddonListRequest: _options.ForwardAcoreAddonInfoAsRetailAddonListRequest,
                        forwardAcoreTutorialFlagsAsRetailTutorialFlags: _options.ForwardAcoreTutorialFlagsAsRetailTutorialFlags,
                        getEnterEncryptedModeFrame: () =>
                        {
                            if (bridgeState.TryGetRetailEnterEncryptedModeFrame(out byte[] frame) && frame.Length > 0)
                            {
                                return frame;
                            }

                            return null;
                        },
                        onDeferredBootstrapPrepared: (payload, stagedOpcodes) =>
                        {
                            bridgeState.QueueDeferredPostAuthPayload(payload, stagedOpcodes);
                        },
                        onEnterEncryptedModeSent: () =>
                        {
                            bridgeState.TryTransitionStage(
                                BridgeStage.ENTER_ENCRYPTED_SENT,
                                "Retail SMSG_ENTER_ENCRYPTED_MODE sent.");
                        },
                        onEnterEncryptedAwaitStart: stagedOpcodes =>
                        {
                            bridgeState.BeginEnterEncryptedAwait();
                            bridgeState.MarkEnterEncryptedAwaitStart(stagedOpcodes, _options.EnterEncryptedModeAckTimeoutMs);
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Waiting for CMSG_ENTER_ENCRYPTED_MODE_ACK. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, PendingRetail={PendingRetail}",
                                connectionId,
                                _options.EnterEncryptedModeAckTimeoutMs,
                                stagedOpcodes);
                        },
                        onBootstrapFlushedWithoutAck: (bytes, stagedOpcodes) =>
                        {
                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Post-auth bootstrap flushed without ACK gate.");
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Ack-gate disabled. Flushed post-auth bootstrap immediately. ConnectionId={ConnectionId}, Bytes={Bytes}, Retail={Retail}",
                                connectionId,
                                bytes,
                                stagedOpcodes);
                        },
                        onBootstrapSuppressedForProbe: (bytes, stagedOpcodes) =>
                        {
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_suppressed_for_probe",
                                passed: false,
                                expected: "bootstrap should flush in milestone scenario",
                                actual: "bootstrap suppressed by probe mode");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Probe mode: suppressed post-auth bootstrap after ENTER_ENCRYPTED_MODE. ConnectionId={ConnectionId}, SuppressedBytes={Bytes}, Retail={Retail}",
                                connectionId,
                                bytes,
                                stagedOpcodes);
                        },
                        onCharEnumReceived: () =>
                        {
                            if (!bridgeState.TryTransitionStage(
                                    BridgeStage.CHAR_ENUM_RECEIVED,
                                    "AC SMSG_CHAR_ENUM mapped to Retail SMSG_ENUM_CHARACTERS_RESULT."))
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][STATE] CHAR_ENUM_RECEIVED transition rejected. ConnectionId={ConnectionId}, Stage={Stage}",
                                    connectionId,
                                    bridgeState.CurrentStage);
                            }
                        },
                        onControlledUnlockApplied: (acPayloadBytes, retailPayloadBytes) =>
                        {
                            _logger.LogInformation(
                                "[WorldProxy][UNLOCK] Controlled empty-char enum unlock applied. ConnectionId={ConnectionId}, AcorePayloadBytes={AcorePayloadBytes}, RetailPayloadBytes={RetailPayloadBytes}",
                                connectionId,
                                acPayloadBytes,
                                retailPayloadBytes);
                        },
                        onFrameDecoded: (opcode, payloadBytes) =>
                        {
                            // Limit frame spam while collecting first handshake map.
                            if (acServerFramesLogged < 32)
                            {
                                acServerFramesLogged++;
                                _logger.LogInformation(
                                    "[WorldProxy][AC->CLIENT FRAME] ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                                    connectionId,
                                    opcode,
                                    payloadBytes);
                            }
                        },
                        onDroppedOpcode: (opcode, payloadBytes) =>
                        {
                            _logger.LogInformation(
                                "[WorldProxy][MAP] Unmapped AC opcode dropped. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                                connectionId,
                                opcode,
                                payloadBytes);
                        });
                    _logger.LogInformation(
                        "[WorldProxy][CRYPT] AC recv header crypt enabled. ConnectionId={ConnectionId}",
                        connectionId);
                }

                if (direction == "world->client" &&
                    !firstPostAuthDumpedServer &&
                    bridgeState.TryGetAcoreHeaderCrypt(out _))
                {
                    firstPostAuthDumpedServer = true;
                    _logger.LogInformation(
                        "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, Math.Max(DefaultDumpBytes, _options.FirstPacketDumpBytes)));
                }

                if (direction == "client->world" &&
                    !firstPostAuthDumpedClient &&
                    bridgeState.TryGetAcoreHeaderCrypt(out _))
                {
                    firstPostAuthDumpedClient = true;
                    _logger.LogInformation(
                        "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, Math.Max(DefaultDumpBytes, _options.FirstPacketDumpBytes)));

                    if (RetailFrameCodec.TryDecodeRetailWorldFrame(buffer, out uint retailBodyLength, out uint retailOpcode))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][POSTAUTH-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, RetailBodyLength={RetailBodyLength}, RetailOpcode=0x{RetailOpcode:X8}",
                            connectionId,
                            direction,
                            retailBodyLength,
                            retailOpcode);
                    }
                }

                bool handledByBridge = false;
                if (direction == "world->client" &&
                    _options.EnableAcoreToRetailAuthChallengeBridgeProbe &&
                    !firstAcoreChallengeBridged &&
                    TryBuildRetailAuthChallengeFromAcore(
                        buffer,
                        _options.RetailAuthChallengeRandomizeDosBlock,
                        out byte[] retailFrame,
                        out int consumedBytes,
                        out RetailAuthChallengeProof authChallengeProof))
                {
                    firstAcoreChallengeBridged = true;
                    handledByBridge = true;

                    if (_options.ProbeRetailAuthChallengeCountAsPreAckWorldFrame)
                    {
                        if (!bridgeState.TryProtectRetailServerFrame(
                                retailFrame,
                                out byte[] protectedAuthChallengeFrame,
                                out _,
                                out string? protectError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][CRYPT] Failed to protect bridged Retail auth challenge frame. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                protectError ?? "<unknown>");
                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        writer.Write(protectedAuthChallengeFrame);
                        totalBytes += protectedAuthChallengeFrame.Length;
                    }
                    else
                    {
                        writer.Write(retailFrame);
                        totalBytes += retailFrame.Length;
                    }

                    _logger.LogInformation(
                        "[WorldProxy][BRIDGE] Translated first AC auth challenge to Retail frame. ConnectionId={ConnectionId}, InBytes={InBytes}, OutBytes={OutBytes}",
                        connectionId,
                        consumedBytes,
                        retailFrame.Length);

                    if (_options.EnableProofPack)
                    {
                        try
                        {
                            AuthChallengeProofArtifacts artifacts = HandshakeDiagnosticsWriters.WriteAuthChallengeProofPack(
                                connectionId,
                                WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                                authChallengeProof);
                            _logger.LogInformation(
                                "[WorldProxy][PROOF] Auth challenge proof written. ConnectionId={ConnectionId}, Hex={HexPath}, Json={JsonPath}",
                                connectionId,
                                artifacts.HexPath,
                                artifacts.MetadataJsonPath);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                        {
                            _logger.LogWarning(
                                ex,
                                "[WorldProxy][PROOF] Failed to write auth challenge proof. ConnectionId={ConnectionId}",
                                connectionId);
                        }
                    }

                    if (buffer.Length > consumedBytes)
                    {
                        foreach (ReadOnlyMemory<byte> segment in buffer.Slice(consumedBytes))
                        {
                            writer.Write(segment.Span);
                            totalBytes += segment.Length;
                        }
                    }
                }
                else if (direction == "client->world" &&
                    _options.EnableRetailToAcoreAuthSessionBridge &&
                    !firstRetailAuthSessionBridged &&
                    bridgeState.TryGetAcoreAuthSeed(out uint authSeed) &&
                    RetailAuthSessionParser.TryParseRetailAuthSessionFrame(
                        buffer,
                        RetailOpcodeAuthSession,
                        RetailAuthFixedPayloadBytes,
                        out RetailAuthSessionFrame retailAuthFrame))
                {
                    if (_options.ProbeRetailAuthSessionCountAsPreAckClientFrame)
                    {
                        byte[] retailAuthWireFrame = GC.AllocateUninitializedArray<byte>(retailAuthFrame.RawFrameBytes);
                        buffer.Slice(0, retailAuthFrame.RawFrameBytes).CopyTo(retailAuthWireFrame);
                        if (!bridgeState.TryDecryptRetailClientFrame(retailAuthWireFrame, out _, out string? decryptError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][CRYPT] Failed to count Retail CMSG_AUTH_SESSION as pre-ACK client frame. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                decryptError ?? "<unknown>");
                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Counted Retail CMSG_AUTH_SESSION as pre-ACK client frame for counter continuity. ConnectionId={ConnectionId}, FrameBytes={FrameBytes}",
                            connectionId,
                            retailAuthFrame.RawFrameBytes);
                    }

                    AcoreAuthSessionBridgeResult? authBridgeResult = await TryBuildAcoreAuthSessionFrameAsync(
                            authSeed,
                            retailAuthFrame,
                            bridgeState,
                            cancellationToken)
                        .ConfigureAwait(false);

                    if (authBridgeResult is not null)
                    {
                        AcoreAuthSessionBridgeResult bridge = authBridgeResult.Value;
                        firstRetailAuthSessionBridged = true;
                        handledByBridge = true;

                        writer.Write(bridge.Frame);
                        totalBytes += bridge.Frame.Length;

                        bridgeState.TrySetAcoreHeaderCrypt(bridge.HeaderCrypt);
                        if (bridgeState.TryGetAcoreServerChallenge(out byte[] serverChallenge))
                        {
                                if (EnterEncryptedModeFramePreparer.TryPrepareRetailEnterEncryptedModeFrame(
                                    _options,
                                    bridge.SessionKey,
                                    bridge.BnetKeyData64,
                                    retailAuthFrame.LocalChallenge32,
                                    serverChallenge,
                                    defaultRetailOpcode: _enterEncryptedModeOpcode,
                                    out byte[] enterEncryptedModeFrame,
                                    out uint enterEncryptedModeOpcodeUsed,
                                    out string? enterEncryptedModeError,
                                    out string keySource,
                                    out string wireFormat,
                                    out byte[] retailWorldEncryptKey32,
                                    out EnterEncryptedModeProof proof))
                                {
                                    if (_options.EnterEncryptedModeParityGateEnabled)
                                    {
                                        string runlogsDir = WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options);
                                        string projectRoot = WorldGatewayPathResolver.ResolveProjectRoot();
                                        EnterEncryptedPayloadParityResult parity = HandshakeDiagnosticsWriters.EvaluateEnterEncryptedPayloadParity(
                                            _options,
                                            enterEncryptedModeFrame.AsSpan(20),
                                            runlogsDir,
                                            projectRoot);
                                        if (!parity.FixtureFound)
                                        {
                                            _logger.LogWarning(
                                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE fixture is unavailable. Gate skipped for this run. ConnectionId={ConnectionId}, FixturePath={FixturePath}, Error={Error}",
                                                connectionId,
                                                parity.FixturePath,
                                                parity.Error ?? "<unknown>");
                                        }
                                        else if (!parity.PayloadMatch)
                                        {
                                            _logger.LogError(
                                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload mismatch. ConnectionId={ConnectionId}, FixturePath={FixturePath}, ExpectedLen={ExpectedLen}, ActualLen={ActualLen}, DiffCount={DiffCount}, FirstDiffIndex={FirstDiffIndex}, Expected=0x{ExpectedByte:X2}, Actual=0x{ActualByte:X2}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}. Closing connection.",
                                                connectionId,
                                                parity.FixturePath,
                                                parity.ExpectedLength,
                                                parity.ActualLength,
                                                parity.DiffCount,
                                                parity.FirstDiffIndex ?? -1,
                                                parity.FirstExpectedByte ?? (byte)0,
                                                parity.FirstActualByte ?? (byte)0,
                                                parity.SignatureBytesIgnored,
                                                parity.SignatureOffset ?? -1,
                                                parity.SignatureBytes);
                                            reader.AdvanceTo(buffer.End);
                                            return totalBytes;
                                        }
                                        else
                                        {
                                            _logger.LogInformation(
                                                "[WorldProxy][PARITY-GATE] ENTER_ENCRYPTED_MODE payload parity passed. ConnectionId={ConnectionId}, FixturePath={FixturePath}, PayloadBytes={PayloadBytes}, SignatureBytesIgnored={SignatureBytesIgnored}, SignatureOffset={SignatureOffset}, SignatureBytes={SignatureBytes}",
                                                connectionId,
                                                parity.FixturePath,
                                                parity.ActualLength,
                                                parity.SignatureBytesIgnored,
                                                parity.SignatureOffset ?? -1,
                                                parity.SignatureBytes);
                                        }
                                    }

                                    bridgeState.TrySetRetailEnterEncryptedModeFrame(enterEncryptedModeFrame);
                                    if (retailWorldEncryptKey32.Length == 32)
                                    {
                                        bridgeState.TrySetRetailWorldEncryptKey(retailWorldEncryptKey32);
                                    }
                                    else
                                    {
                                        _logger.LogWarning(
                                            "[WorldProxy][BRIDGE] Retail world encrypt key is unavailable. Post-ACK world packet crypto cannot be enabled. ConnectionId={ConnectionId}, KeyBytes={KeyBytes}, KeySource={KeySource}",
                                            connectionId,
                                            retailWorldEncryptKey32.Length,
                                            keySource);
                                    }
                                    _logger.LogInformation(
                                        "[WorldProxy][BRIDGE] Prepared Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, PayloadBytes={PayloadBytes}, KeySource={KeySource}, WireFormat={WireFormat}, RegionGroup={RegionGroup}, IncludeRegionGroup={IncludeRegionGroup}, Enabled={Enabled}, EnabledAsByte={EnabledAsByte}, PreferBnetKeyData={PreferBnetKeyData}",
                                        connectionId,
                                        enterEncryptedModeOpcodeUsed,
                                        enterEncryptedModeFrame.Length - 20,
                                    keySource,
                                    wireFormat,
                                    _options.EnterEncryptedModeRegionGroup,
                                    _options.EnterEncryptedModeIncludeRegionGroup,
                                    _options.EnterEncryptedModeEnabled,
                                    _options.EnterEncryptedModeEnabledAsByte,
                                    _options.EnterEncryptedModePreferBnetKeyData);

                                if (_options.EnableProofPack)
                                {
                                    try
                                    {
                                        ProofPackArtifacts artifacts = HandshakeDiagnosticsWriters.WriteEnterEncryptedProofPack(
                                            connectionId,
                                            _options,
                                            proof,
                                            bridge.AccountId,
                                            WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                                            WorldGatewayPathResolver.ResolveProjectRoot());
                                        bridgeState.SetProofPackArtifacts(artifacts.HexPath, artifacts.MetadataJsonPath, artifacts.DiffPath);
                                        _logger.LogInformation(
                                            "[WorldProxy][PROOF] Proof pack written. ConnectionId={ConnectionId}, Hex={HexPath}, Json={JsonPath}, Diff={DiffPath}",
                                            connectionId,
                                            artifacts.HexPath,
                                            artifacts.MetadataJsonPath,
                                            artifacts.DiffPath);
                                    }
                                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                                    {
                                        _logger.LogWarning(
                                            ex,
                                            "[WorldProxy][PROOF] Failed to write proof pack artifacts. ConnectionId={ConnectionId}",
                                            connectionId);
                                    }
                                }
                            }
                            else
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][BRIDGE] Failed to build Retail SMSG_ENTER_ENCRYPTED_MODE frame. ConnectionId={ConnectionId}, Error={Error}",
                                    connectionId,
                                    enterEncryptedModeError ?? "<unknown>");
                            }
                        }

                        _logger.LogInformation(
                            "[WorldProxy][BRIDGE] Translated Retail CMSG_AUTH_SESSION to AC CMSG_AUTH_SESSION. ConnectionId={ConnectionId}, InBytes={InBytes}, OutBytes={OutBytes}, AccountId={AccountId}, AccountIdSource={AccountIdSource}, RegionId={RegionId}, BattlegroupId={BattlegroupId}, RetailRealmId=0x{RetailRealmId:X8}, AcoreRealmId={AcoreRealmId}",
                            connectionId,
                            retailAuthFrame.RawFrameBytes,
                            bridge.Frame.Length,
                            bridge.AccountId,
                            bridge.AccountIdSource,
                            retailAuthFrame.RegionId,
                            retailAuthFrame.BattlegroupId,
                            retailAuthFrame.RealmId,
                            _options.AcoreRealmId);
                        bridgeState.TryTransitionStage(
                            BridgeStage.AUTH_SESSION_BRIDGED,
                            "Retail CMSG_AUTH_SESSION translated to AC CMSG_AUTH_SESSION.");

                        if (buffer.Length > retailAuthFrame.RawFrameBytes)
                        {
                            foreach (ReadOnlyMemory<byte> segment in buffer.Slice(retailAuthFrame.RawFrameBytes))
                            {
                                writer.Write(segment.Span);
                                totalBytes += segment.Length;
                            }
                        }
                    }
                    else
                    {
                        _logger.LogWarning(
                            "[WorldProxy][BRIDGE] Failed to translate Retail CMSG_AUTH_SESSION in strict mode. ConnectionId={ConnectionId}. Closing connection.",
                            connectionId);

                        reader.AdvanceTo(buffer.End);
                        return totalBytes;
                    }
                }

                if (!handledByBridge)
                {
                    if (direction == "client->world" && retailPostAuthClientTranslator is not null)
                    {
                        if (!retailPostAuthClientTranslator.TryTransform(
                                buffer,
                                writer,
                                onDroppedOpcode: (opcode, payloadBytes) =>
                                {
                                    _logger.LogInformation(
                                        "[WorldProxy][MAP] Unmapped Retail opcode dropped. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, PayloadBytes={PayloadBytes}",
                                        connectionId,
                                        opcode,
                                        payloadBytes);
                                },
                                out long transformedBytes,
                                out string? transformError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][MAP] Failed to translate Retail post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                transformError ?? "<unknown>");

                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        totalBytes += transformedBytes;
                    }
                    else if (direction == "world->client" && acorePostAuthServerTranslator is not null)
                    {
                        if (!acorePostAuthServerTranslator.TryTransform(buffer, writer, out long transformedBytes, out string? transformError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][MAP] Failed to translate AC post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                transformError ?? "<unknown>");

                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        totalBytes += transformedBytes;
                    }
                    else
                    {
                        foreach (ReadOnlyMemory<byte> segment in buffer)
                        {
                            writer.Write(segment.Span);
                            totalBytes += segment.Length;
                        }
                    }
                }

                FlushResult flushResult = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                if (flushResult.IsCanceled || flushResult.IsCompleted)
                {
                    reader.AdvanceTo(buffer.End);
                    break;
                }

                if (direction == "client->world" && bridgeState.ConsumeClientRequestedDisconnect())
                {
                    _logger.LogInformation(
                        "[WorldProxy][MAP] Client requested world disconnect. ConnectionId={ConnectionId}, Direction={Direction}. Ending relay side.",
                        connectionId,
                        direction);
                    reader.AdvanceTo(buffer.End);
                    break;
                }

                if (direction == "world->client" && bridgeState.IsAwaitingEnterEncryptedAck)
                {
                    bool fallbackFlushEnabled =
                        _bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck &&
                        _options.BootstrapFlushTriggerFallbackTimeoutMs > 0;
                    int ackWaitTimeoutMs = _options.EnterEncryptedModeAckTimeoutMs;
                    if (fallbackFlushEnabled)
                    {
                        ackWaitTimeoutMs = Math.Min(ackWaitTimeoutMs, _options.BootstrapFlushTriggerFallbackTimeoutMs);
                    }

                    TimeSpan timeout = TimeSpan.FromMilliseconds(ackWaitTimeoutMs);
                    long waitStartMs = Environment.TickCount64;
                    bool acked = bridgeState.WaitForEnterEncryptedAck(timeout);
                    long elapsedMs = Environment.TickCount64 - waitStartMs;
                    bool fallbackFlushWithoutAck = false;
                    string ackExpected = fallbackFlushEnabled
                        ? $"ACK within {ackWaitTimeoutMs}ms (fallback window)"
                        : $"ACK within {_options.EnterEncryptedModeAckTimeoutMs}ms";

                    if (!acked)
                    {
                        bridgeState.TryPeekDeferredPostAuthInfo(out int pendingBytes, out string pendingRetail);
                        bridgeState.MarkEnterEncryptedAckTimeout(pendingBytes, pendingRetail);
                        if (fallbackFlushEnabled)
                        {
                            fallbackFlushWithoutAck = true;
                            bridgeState.MarkTemporalInvariant(
                                name: "enter_encrypted_ack_within_timeout",
                                passed: false,
                                expected: ackExpected,
                                actual: $"no ACK in {elapsedMs}ms; continuing with fallback bootstrap flush (pending bytes={pendingBytes})");
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_flush_trigger_fallback_timeout",
                                passed: true,
                                expected: "flush deferred bootstrap when post-ACK trigger is absent within fallback timeout",
                                actual: $"fallback timeout {ackWaitTimeoutMs}ms reached; pending retail={pendingRetail}");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] ACK not observed within fallback window. ConnectionId={ConnectionId}, FallbackTimeoutMs={TimeoutMs}, ElapsedMs={ElapsedMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}. Proceeding with deferred bootstrap flush without ACK.",
                                connectionId,
                                ackWaitTimeoutMs,
                                elapsedMs,
                                pendingBytes,
                                pendingRetail);
                        }
                        else
                        {
                            bridgeState.MarkTemporalInvariant(
                                name: "enter_encrypted_ack_within_timeout",
                                passed: false,
                                expected: ackExpected,
                                actual: $"timeout after {elapsedMs}ms (pending bytes={pendingBytes})");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Timeout waiting for CMSG_ENTER_ENCRYPTED_MODE_ACK. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, ElapsedMs={ElapsedMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}",
                                connectionId,
                                _options.EnterEncryptedModeAckTimeoutMs,
                                elapsedMs,
                                pendingBytes,
                                pendingRetail);

                            bridgeState.ResetEnterEncryptedAwait();
                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }
                    }

                    if (!fallbackFlushWithoutAck)
                    {
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] CMSG_ENTER_ENCRYPTED_MODE_ACK confirmed. ConnectionId={ConnectionId}, ElapsedMs={ElapsedMs}",
                            connectionId,
                            elapsedMs);
                        bridgeState.MarkTemporalInvariant(
                            name: "enter_encrypted_ack_within_timeout",
                            passed: true,
                            expected: ackExpected,
                            actual: $"ACK confirmed in {elapsedMs}ms");
                        bridgeState.MarkEnterEncryptedAckConfirmed(elapsedMs);
                        if (_options.EnableRetailWorldPacketCryptOnAck)
                        {
                            if (!bridgeState.TryEnableRetailWorldCrypt(out string? enableError))
                            {
                                _logger.LogWarning(
                                    "[WorldProxy][CRYPT] Failed to enable Retail world packet crypt after ACK confirmation. ConnectionId={ConnectionId}, Error={Error}",
                                    connectionId,
                                    enableError ?? "<unknown>");
                            }
                        }
                        else
                        {
                            _logger.LogInformation(
                                "[WorldProxy][CRYPT] Retail world packet crypt-on-ACK disabled by config after ACK confirmation. ConnectionId={ConnectionId}",
                                connectionId);
                        }
                    }
                    else
                    {
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Continuing with deferred bootstrap flush without ACK confirmation due to configured fallback timeout. ConnectionId={ConnectionId}",
                            connectionId);
                    }

                    bridgeState.ResetEnterEncryptedAwait();

                    bool shouldFlushDeferredNow = true;
                    string deferredFlushPath = fallbackFlushWithoutAck ? "fallback_without_ack" : "ack_gate";
                    if (!fallbackFlushWithoutAck &&
                        _bootstrapFlushTriggerMode == BootstrapFlushTriggerMode.FirstClientPostAckNonAck)
                    {
                        int triggerTimeoutMs = _options.EnterEncryptedModeAckTimeoutMs;
                        if (_options.BootstrapFlushTriggerFallbackTimeoutMs > 0)
                        {
                            triggerTimeoutMs = Math.Min(triggerTimeoutMs, _options.BootstrapFlushTriggerFallbackTimeoutMs);
                        }

                        bridgeState.BeginPostAckNonAckBootstrapTriggerAwait();
                        _logger.LogInformation(
                            "[WorldProxy][HANDSHAKE] Deferred post-auth bootstrap flush is waiting for first post-ACK non-ACK client frame. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}",
                            connectionId,
                            triggerTimeoutMs);

                        TimeSpan triggerTimeout = TimeSpan.FromMilliseconds(triggerTimeoutMs);
                        long triggerWaitStartMs = Environment.TickCount64;
                        bool triggerObserved = bridgeState.WaitForPostAckNonAckBootstrapTrigger(triggerTimeout);
                        long triggerElapsedMs = Environment.TickCount64 - triggerWaitStartMs;
                        bridgeState.EndPostAckNonAckBootstrapTriggerAwait();

                        if (triggerObserved &&
                            bridgeState.TryGetPostAckNonAckBootstrapTriggerOpcode(out uint triggerOpcode))
                        {
                            deferredFlushPath = "post_ack_non_ack_trigger";
                            bridgeState.MarkPostAckNonAckBootstrapTriggerWait(triggerElapsedMs);
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_flush_trigger_post_ack_non_ack",
                                passed: true,
                                expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                                actual: $"triggered by opcode=0x{triggerOpcode:X8} after {triggerElapsedMs}ms");
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger fired. ConnectionId={ConnectionId}, TriggerOpcode=0x{Opcode:X8}, WaitMs={WaitMs}",
                                connectionId,
                                triggerOpcode,
                                triggerElapsedMs);
                        }
                        else
                        {
                            bridgeState.TryPeekDeferredPostAuthInfo(out int pendingBytes, out string pendingRetail);
                            bool fallbackFlushOnTriggerTimeout = _options.BootstrapFlushTriggerFallbackTimeoutMs > 0;
                            if (fallbackFlushOnTriggerTimeout)
                            {
                                shouldFlushDeferredNow = true;
                                deferredFlushPath = "post_ack_non_ack_fallback_timeout";
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_trigger_post_ack_non_ack",
                                    passed: false,
                                    expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                                    actual: $"timeout after {triggerElapsedMs}ms; fallback flush enabled (pending bytes={pendingBytes}, pending retail={pendingRetail})");
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_trigger_post_ack_non_ack_fallback",
                                    passed: true,
                                    expected: "flush deferred bootstrap on trigger-timeout when fallback timeout is configured",
                                    actual: $"fallback timeout {triggerTimeoutMs}ms reached; flushing pending retail={pendingRetail}");
                                _logger.LogWarning(
                                    "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, WaitMs={WaitMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}. Proceeding with fallback flush.",
                                    connectionId,
                                    triggerTimeoutMs,
                                    triggerElapsedMs,
                                    pendingBytes,
                                    pendingRetail);
                            }
                            else
                            {
                                shouldFlushDeferredNow = false;
                                deferredFlushPath = "post_ack_non_ack_timeout_no_flush";
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_trigger_post_ack_non_ack",
                                    passed: false,
                                    expected: "flush bootstrap only after first client post-ACK non-ACK frame",
                                    actual: $"timeout after {triggerElapsedMs}ms (pending bytes={pendingBytes}, pending retail={pendingRetail})");
                                _logger.LogWarning(
                                    "[WorldProxy][HANDSHAKE] Deferred bootstrap flush trigger timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}, WaitMs={WaitMs}, PendingBytes={PendingBytes}, PendingRetail={PendingRetail}",
                                    connectionId,
                                    triggerTimeoutMs,
                                    triggerElapsedMs,
                                    pendingBytes,
                                    pendingRetail);
                            }
                        }
                    }

                    bridgeState.MarkDeferredFlushPath(deferredFlushPath);
                    if (shouldFlushDeferredNow &&
                        bridgeState.TryTakeDeferredPostAuthPayload(out byte[] deferredPayload, out string stagedOpcodes) &&
                        deferredPayload.Length > 0)
                    {
                        if (_options.SuppressPostAuthBootstrapForProbe && !_options.ProbeBareAuthResponseOnly)
                        {
                            bridgeState.MarkDeferredFlushPath("suppressed");
                            bridgeState.MarkTemporalInvariant(
                                name: "bootstrap_suppressed_for_probe",
                                passed: false,
                                expected: "bootstrap should flush in milestone scenario",
                                actual: "bootstrap suppressed by probe mode");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Probe mode: suppressed deferred post-auth bootstrap after ACK gate. ConnectionId={ConnectionId}, SuppressedBytes={Bytes}, Retail={Retail}",
                                connectionId,
                                deferredPayload.Length,
                                stagedOpcodes);
                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Deferred post-auth bootstrap suppressed by probe mode after ACK gate.");

                            if (_options.ProbeExplicitBootstrapFlushMarker)
                            {
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_marker_explicit",
                                    passed: true,
                                    expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                                    actual: $"path=suppressed;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                                    connectionId,
                                    "suppressed",
                                    deferredPayload.Length,
                                    stagedOpcodes);
                            }
                        }
                        else if (!RetailFrameCodec.TrySplitRetailWorldFrames(deferredPayload, out List<RetailFrameChunk> deferredFrames, out string? splitError))
                        {
                            bridgeState.MarkDeferredFlushPath("raw_payload_fallback");
                            _logger.LogWarning(
                                "[WorldProxy][HANDSHAKE] Failed to split deferred post-auth bootstrap into Retail frames. ConnectionId={ConnectionId}, Error={Error}, Bytes={Bytes}, Retail={Retail}",
                                connectionId,
                                splitError ?? "<unknown>",
                                deferredPayload.Length,
                                stagedOpcodes);

                            writer.Write(deferredPayload);
                            totalBytes += deferredPayload.Length;

                            FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                            if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
                            {
                                reader.AdvanceTo(buffer.End);
                                break;
                            }

                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Deferred post-auth bootstrap flushed after ACK gate (raw payload fallback).");

                            if (_options.ProbeExplicitBootstrapFlushMarker)
                            {
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_marker_explicit",
                                    passed: true,
                                    expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                                    actual: $"path=raw_payload_fallback;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                                    connectionId,
                                    "raw_payload_fallback",
                                    deferredPayload.Length,
                                    stagedOpcodes);
                            }
                        }
                        else
                        {
                            _logger.LogInformation(
                                "[WorldProxy][HANDSHAKE] Flushing deferred post-auth bootstrap. ConnectionId={ConnectionId}, Frames={Frames}, Bytes={Bytes}, Retail={Retail}",
                                connectionId,
                                deferredFrames.Count,
                                deferredPayload.Length,
                                stagedOpcodes);

                            bridgeState.BeginDeferredBootstrapFlush(deferredFrames.Count);
                            bool deferredInterrupted = false;
                            for (int frameIndex = 0; frameIndex < deferredFrames.Count; frameIndex++)
                            {
                                RetailFrameChunk frame = deferredFrames[frameIndex];
                                bool shouldDropFrame = _probeDropDeferredOpcodes.Contains(frame.Opcode);
                                if (_options.ProbeBareAuthResponseOnly &&
                                    frame.Opcode == RetailOpcodeSmsgAuthResponse)
                                {
                                    // In bare AUTH_RESPONSE probe mode, always deliver AUTH_RESPONSE even if
                                    // legacy probe drop list still includes it from previous experiments.
                                    shouldDropFrame = false;
                                }

                                if (shouldDropFrame)
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][HANDSHAKE] Probe mode: dropped deferred frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, BodyLength={BodyLength}",
                                        connectionId,
                                        frameIndex + 1,
                                        deferredFrames.Count,
                                        frame.Opcode,
                                        frame.BodyLength);
                                    continue;
                                }

                                bool isPreludeFrame = frame.Opcode == RetailOpcodeSmsgAuthSequencePrelude;
                                bool isAuthResponseFrame = frame.Opcode == _probeAuthResponseOpcode;
                                if (isAuthResponseFrame)
                                {
                                    bool plainEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(frame.Frame, out string plainEnvelopeActual);
                                    bridgeState.MarkTemporalInvariant(
                                        name: "auth_response_plaintext_envelope_invariant",
                                        passed: plainEnvelopeOk,
                                        expected: "plaintext frame: size=opcode+payload, frame_bytes=16+size, size excludes 12-byte tag",
                                        actual: plainEnvelopeActual);

                                    if (!plainEnvelopeOk)
                                    {
                                        _logger.LogWarning(
                                            "[WorldProxy][ENVELOPE] Plain AUTH_RESPONSE envelope invariant failed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Actual={Actual}",
                                            connectionId,
                                            frame.Opcode,
                                            plainEnvelopeActual);
                                    }
                                }

                                if (!bridgeState.TryProtectRetailServerFrame(
                                        frame.Frame,
                                        out byte[] protectedFrame,
                                        out ulong serverCounterUsed,
                                        out string? protectError))
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][CRYPT] Failed to protect deferred Retail frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, Error={Error}",
                                        connectionId,
                                        frameIndex + 1,
                                        deferredFrames.Count,
                                        frame.Opcode,
                                        protectError ?? "<unknown>");

                                    reader.AdvanceTo(buffer.End);
                                    return totalBytes;
                                }

                                string plainSha256 = Convert.ToHexString(SHA256.HashData(frame.Frame));
                                string protectedSha256 = Convert.ToHexString(SHA256.HashData(protectedFrame));
                                string protectedTagHex = Convert.ToHexString(protectedFrame.AsSpan(4, 12));
                                DeferredFrameParityResult deferredParity = new(
                                    Status: "not_evaluated",
                                    FixturePath: null,
                                    DiffOffset: null,
                                    ExpectedBytes: null,
                                    ActualBytes: null);

                                if (isPreludeFrame)
                                {
                                    bool protectedEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(protectedFrame, out string preludeEnvelopeActual);
                                    uint protectedSize = protectedEnvelopeOk
                                        ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(0, 4))
                                        : 0u;
                                    uint protectedOpcode = protectedEnvelopeOk
                                        ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(16, 4))
                                        : 0u;
                                    bool sizePreserved = protectedEnvelopeOk &&
                                        protectedSize == (uint)frame.BodyLength &&
                                        protectedFrame.Length == frame.Frame.Length;
                                    bool opcodeEncryptedWhenCryptActive = !bridgeState.IsRetailWorldCryptActive ||
                                        protectedOpcode != frame.Opcode;
                                    bool preludeInvariantPassed = sizePreserved && opcodeEncryptedWhenCryptActive;
                                    bridgeState.MarkTemporalInvariant(
                                        name: "prelude_encrypted_envelope_invariant",
                                        passed: preludeInvariantPassed,
                                        expected: "if world crypt is active, prelude opcode bytes must be encrypted while envelope size stays preserved",
                                        actual: $"{preludeEnvelopeActual};world_crypt_active={bridgeState.IsRetailWorldCryptActive};plain_opcode=0x{frame.Opcode:X8};protected_opcode=0x{protectedOpcode:X8};size_preserved={sizePreserved}");

                                    _logger.LogInformation(
                                        "[WorldProxy][ENVELOPE] Prelude frame protected. ConnectionId={ConnectionId}, PlainOpcode=0x{PlainOpcode:X8}, ProtectedOpcode=0x{ProtectedOpcode:X8}, WorldCryptActive={WorldCryptActive}, SizePreserved={SizePreserved}",
                                        connectionId,
                                        frame.Opcode,
                                        protectedOpcode,
                                        bridgeState.IsRetailWorldCryptActive,
                                        sizePreserved);
                                }

                                if (isAuthResponseFrame)
                                {
                                    bool protectedEnvelopeOk = RetailEnvelopeBuilder.TryValidateRetailWorldEnvelope(protectedFrame, out string protectedEnvelopeActual);
                                    uint protectedSize = protectedEnvelopeOk
                                        ? BinaryPrimitives.ReadUInt32LittleEndian(protectedFrame.AsSpan(0, 4))
                                        : 0u;
                                    bool sizePreserved = protectedEnvelopeOk &&
                                        protectedSize == (uint)frame.BodyLength &&
                                        protectedFrame.Length == frame.Frame.Length;
                                    bridgeState.MarkTemporalInvariant(
                                        name: "auth_response_encrypted_envelope_invariant",
                                        passed: sizePreserved,
                                        expected: "encrypted frame keeps plaintext size and total length (16+size), with 12-byte tag in header",
                                        actual: $"{protectedEnvelopeActual};size_preserved={sizePreserved};expected_body={frame.BodyLength};protected_size={protectedSize};protected_bytes={protectedFrame.Length};plain_bytes={frame.Frame.Length}");

                                    if (!sizePreserved)
                                    {
                                        _logger.LogWarning(
                                            "[WorldProxy][ENVELOPE] Encrypted AUTH_RESPONSE envelope invariant failed. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Actual={Actual}",
                                            connectionId,
                                            frame.Opcode,
                                            protectedEnvelopeActual);
                                    }
                                }

                                if (frameIndex == 0)
                                {
                                    deferredParity = HandshakeDiagnosticsWriters.EvaluateFirstDeferredFrameParity(
                                        _options.ProbeFirstDeferredFrameParityFixturePath,
                                        protectedFrame,
                                        WorldGatewayPathResolver.ResolveProjectRoot());
                                    bool parityConfigured = !string.IsNullOrWhiteSpace(_options.ProbeFirstDeferredFrameParityFixturePath);
                                    bool parityPassed = !parityConfigured ||
                                        string.Equals(deferredParity.Status, "match", StringComparison.OrdinalIgnoreCase);
                                    string parityExpected = parityConfigured
                                        ? "first deferred protected frame should byte-match configured fixture"
                                        : "fixture not configured; parity check is informational only";
                                    string parityActual = $"status={deferredParity.Status};fixture={deferredParity.FixturePath ?? "<none>"};diff_offset={deferredParity.DiffOffset?.ToString(CultureInfo.InvariantCulture) ?? "<none>"};expected={deferredParity.ExpectedBytes ?? "<none>"};actual={deferredParity.ActualBytes ?? "<none>"}";
                                    bridgeState.MarkTemporalInvariant(
                                        name: "deferred_first_frame_fixture_parity",
                                        passed: parityPassed,
                                        expected: parityExpected,
                                        actual: parityActual);

                                    _logger.LogInformation(
                                        "[WorldProxy][HANDSHAKE] First deferred frame evidence. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, Counter={Counter}, Tag={Tag}, PlainSha256={PlainSha256}, ProtectedSha256={ProtectedSha256}, ParityStatus={ParityStatus}, ParityDiffOffset={ParityDiffOffset}, ParityFixture={ParityFixture}",
                                        connectionId,
                                        frame.Opcode,
                                        serverCounterUsed,
                                        protectedTagHex,
                                        plainSha256,
                                        protectedSha256,
                                        deferredParity.Status,
                                        deferredParity.DiffOffset,
                                        deferredParity.FixturePath ?? "<none>");
                                }

                                writer.Write(protectedFrame);
                                totalBytes += protectedFrame.Length;

                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Sent deferred frame. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}, BodyLength={BodyLength}, FrameBytes={FrameBytes}, Counter={Counter}, Tag={Tag}",
                                    connectionId,
                                    frameIndex + 1,
                                    deferredFrames.Count,
                                    frame.Opcode,
                                    frame.BodyLength,
                                    protectedFrame.Length,
                                    serverCounterUsed,
                                    protectedTagHex);

                                bridgeState.MarkDeferredFrameSent(
                                    frameIndex + 1,
                                    deferredFrames.Count,
                                    frame.Opcode,
                                    frame.BodyLength,
                                    protectedFrame.Length,
                                    serverCounterUsed,
                                    plainSha256,
                                    protectedSha256,
                                    protectedTagHex,
                                    deferredParity);

                                FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                                if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
                                {
                                    _logger.LogWarning(
                                        "[WorldProxy][HANDSHAKE] Deferred frame flush interrupted. ConnectionId={ConnectionId}, Index={Index}, Total={Total}, Opcode=0x{Opcode:X8}",
                                        connectionId,
                                        frameIndex + 1,
                                        deferredFrames.Count,
                                        frame.Opcode);

                                    deferredInterrupted = true;
                                    break;
                                }
                            }

                            if (deferredInterrupted)
                            {
                                reader.AdvanceTo(buffer.End);
                                return totalBytes;
                            }

                            bridgeState.TryTransitionStage(
                                BridgeStage.BOOTSTRAP_FLUSHED,
                                "Deferred post-auth bootstrap flushed after ACK gate.");

                            if (_options.ProbeExplicitBootstrapFlushMarker)
                            {
                                bridgeState.MarkTemporalInvariant(
                                    name: "bootstrap_flush_marker_explicit",
                                    passed: true,
                                    expected: "explicit marker emitted when deferred bootstrap flush path is reached",
                                    actual: $"path=protected_frames;bytes={deferredPayload.Length};retail={stagedOpcodes}");
                                _logger.LogInformation(
                                    "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
                                    connectionId,
                                    "protected_frames",
                                    deferredPayload.Length,
                                    stagedOpcodes);
                            }
                        }
                    }
                }
            }

            reader.AdvanceTo(buffer.End);

            if (readResult.IsCanceled || readResult.IsCompleted)
            {
                break;
            }
        }

        return totalBytes;
    }

    private async ValueTask<bool> TryPerformRetailConnectionInitializerAsync(
        uint connectionId,
        NetworkStream downstreamStream,
        CancellationToken relayToken)
    {
        using var initCts = CancellationTokenSource.CreateLinkedTokenSource(relayToken);
        initCts.CancelAfter(_options.InitializerTimeoutMs);

        try
        {
            await downstreamStream.WriteAsync(ServerConnectionInitializer, initCts.Token).ConfigureAwait(false);
            await downstreamStream.FlushAsync(initCts.Token).ConfigureAwait(false);

            byte[] rented = ArrayPool<byte>.Shared.Rent(ClientConnectionInitializer.Length);
            try
            {
                Memory<byte> clientInit = rented.AsMemory(0, ClientConnectionInitializer.Length);
                bool ok = await TryReadExactAsync(downstreamStream, clientInit, initCts.Token).ConfigureAwait(false);
                if (!ok)
                {
                    _logger.LogWarning(
                        "[WorldProxy][INIT] Failed to read client initializer. ConnectionId={ConnectionId}, ExpectedBytes={ExpectedBytes}",
                        connectionId,
                        ClientConnectionInitializer.Length);
                    return false;
                }

                ReadOnlySpan<byte> expected = ClientConnectionInitializer;
                if (!clientInit.Span.SequenceEqual(expected))
                {
                    _logger.LogWarning(
                        "[WorldProxy][INIT] Invalid client initializer. ConnectionId={ConnectionId}, Expected=\"{Expected}\", ActualHex={ActualHex}",
                        connectionId,
                        Encoding.ASCII.GetString(ClientConnectionInitializer),
                        Convert.ToHexString(clientInit.Span));
                    return false;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }

            _logger.LogInformation(
                "[WorldProxy][INIT] Retail world initializer completed. ConnectionId={ConnectionId}",
                connectionId);
            return true;
        }
        catch (OperationCanceledException) when (initCts.IsCancellationRequested)
        {
            _logger.LogWarning(
                "[WorldProxy][INIT] Retail world initializer timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}",
                connectionId,
                _options.InitializerTimeoutMs);
            return false;
        }
        catch (IOException ex)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][INIT] IO error during retail initializer. ConnectionId={ConnectionId}",
                connectionId);
            return false;
        }
        catch (SocketException ex)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][INIT] Socket error during retail initializer. ConnectionId={ConnectionId}",
                connectionId);
            return false;
        }
    }

    private static async ValueTask<bool> TryReadExactAsync(
        NetworkStream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    private static bool TryBuildRetailAuthChallengeFromAcore(
        ReadOnlySequence<byte> buffer,
        bool randomizeDosBlock,
        out byte[] retailFrame,
        out int consumedBytes,
        out RetailAuthChallengeProof proof)
    {
        retailFrame = Array.Empty<byte>();
        consumedBytes = 0;
        proof = default;

        if (buffer.Length < 44)
        {
            return false;
        }

        Span<byte> acFrame = stackalloc byte[44];
        buffer.Slice(0, 44).CopyTo(acFrame);

        ushort sizeBE = BinaryPrimitives.ReadUInt16BigEndian(acFrame[..2]);
        ushort opcodeLE = BinaryPrimitives.ReadUInt16LittleEndian(acFrame.Slice(2, 2));
        if (sizeBE != 42 || opcodeLE != 0x01EC)
        {
            return false;
        }

        Span<byte> acPayload = acFrame.Slice(4, 40);
        Span<byte> retailPayload = stackalloc byte[65];
        uint dosChallenge = BinaryPrimitives.ReadUInt32LittleEndian(acPayload[..4]);
        uint authSeed = BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(4, 4));
        ReadOnlySpan<byte> acChallengeSeed = acPayload.Slice(8, 32);
        Span<byte> dosBlock = retailPayload.Slice(0, 32);
        Span<byte> challengeBlock = retailPayload.Slice(32, 32);
        string dosBlockSource;

        // Retail/TC auth challenge layout:
        // 32 bytes DosChallenge + 32 bytes Challenge + 1 byte DosZeroBits.
        // Optional TC-like mode: dos-challenge block is independent random bytes.
        if (randomizeDosBlock)
        {
            RandomNumberGenerator.Fill(dosBlock);
            dosBlockSource = "random32";
        }
        else
        {
            acChallengeSeed.CopyTo(dosBlock);
            dosBlockSource = "mirror_ac_newseed";
        }

        // Keep challenge block bound to AC new seed so downstream auth bridge remains stable.
        acChallengeSeed.CopyTo(challengeBlock);
        retailPayload[64] = 1;

        retailFrame = GC.AllocateUninitializedArray<byte>(16 + 4 + 65);
        Span<byte> frame = retailFrame;

        BinaryPrimitives.WriteUInt32LittleEndian(frame[..4], 69); // opcode (4) + payload (65)
        frame.Slice(4, 12).Clear(); // tag=0 before encrypted mode
        BinaryPrimitives.WriteUInt32LittleEndian(frame.Slice(16, 4), 0x490000); // SMSG_AUTH_CHALLENGE (Retail/TC)
        retailPayload.CopyTo(frame.Slice(20, 65));

        proof = new RetailAuthChallengeProof(
            TimestampUtc: DateTimeOffset.UtcNow.ToString("O"),
            RetailOpcode: 0x0049_0000,
            AcoreDosChallenge: dosChallenge,
            AcoreAuthSeed: authSeed,
            AcoreNewSeedHex: Convert.ToHexString(acChallengeSeed),
            DosBlockSource: dosBlockSource,
            DosBlockHex: Convert.ToHexString(dosBlock),
            ChallengeBlockHex: Convert.ToHexString(challengeBlock),
            RetailPayloadHex: Convert.ToHexString(retailPayload),
            RetailPayloadBytes: retailPayload.Length);

        consumedBytes = 44;
        return true;
    }

    private async ValueTask<AcoreAuthSessionBridgeResult?> TryBuildAcoreAuthSessionFrameAsync(
        uint authSeed,
        RetailAuthSessionFrame retailFrame,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        try
        {
            int accountId = retailFrame.AccountId;
            string accountIdSource = "retail_payload";
            if (accountId <= 0)
            {
                (accountId, accountIdSource) = await ResolveMissingRetailAccountIdAsync(cancellationToken).ConfigureAwait(false);
                if (accountId > 0)
                {
                    _logger.LogWarning(
                        "[WorldProxy][DB-GATE] Retail AUTH_SESSION accountId missing. Using fallback account id. AccountId={AccountId}, Source={Source}",
                        accountId,
                        accountIdSource);
                }
                else
                {
                    bridgeState.SetEvidenceContext("DB", "db parity gate");
                    bridgeState.MarkTemporalInvariant(
                        name: "db_parity_gate",
                        passed: false,
                        expected: "Retail AUTH_SESSION carries a non-zero accountId or fallback resolution finds one.",
                        actual: "Retail AUTH_SESSION accountId is missing and no fallback account id is available.");
                    _logger.LogWarning(
                        "[WorldProxy][DB-GATE] Rejected before protocol rewrite: Retail auth session has no valid accountId and fallback resolution failed.");
                    return null;
                }
            }

            AcoreSessionMaterial? material = await _worldSessionMaterialRepository.TryReadSessionMaterialByAccountIdAsync(accountId, cancellationToken).ConfigureAwait(false);
            if (material is null && accountIdSource == "config:AuthAccountIdFallback")
            {
                int? latestAccountId = await _worldSessionMaterialRepository.TryReadLatestSessionMaterialAccountIdAsync(cancellationToken).ConfigureAwait(false);
                if (latestAccountId is > 0 && latestAccountId.Value != accountId)
                {
                    AcoreSessionMaterial? latestMaterial = await _worldSessionMaterialRepository.TryReadSessionMaterialByAccountIdAsync(latestAccountId.Value, cancellationToken).ConfigureAwait(false);
                    if (latestMaterial is not null)
                    {
                        accountId = latestAccountId.Value;
                        accountIdSource = "db:adapter_world_session_material.latest";
                        material = latestMaterial;
                        _logger.LogWarning(
                            "[WorldProxy][DB-GATE] AuthAccountIdFallback had no session material; switched to latest adapter world session material. AccountId={AccountId}",
                            accountId);
                    }
                }
            }

            if (material is null)
            {
                bridgeState.SetEvidenceContext("DB", "db parity gate");
                bridgeState.MarkTemporalInvariant(
                    name: "db_parity_gate",
                    passed: false,
                    expected: "Account/session material exists in auth DB for resolved account id.",
                    actual: $"No DB row/material for account id {accountId} (source={accountIdSource}).");
                _logger.LogWarning(
                    "[WorldProxy][BRIDGE] Strict session key lookup failed for AccountId={AccountId}, Source={Source}.",
                    accountId,
                    accountIdSource);
                return null;
            }

            AcoreSessionMaterial account = material.Value;
            RetailAuthSessionFrame effectiveRetailFrame = retailFrame with { AccountId = accountId };
            DbParityGateResult dbGateResult = DbParityGateEvaluator.Evaluate(
                effectiveRetailFrame,
                account,
                AcoreSessionKeyBytes,
                _options.AcoreRealmId,
                _options.AcoreClientBuild);
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: dbGateResult.Passed,
                expected: dbGateResult.Expected,
                actual: dbGateResult.Actual);
            if (!dbGateResult.Passed)
            {
                bridgeState.SetEvidenceContext("DB", "db parity gate");
                _logger.LogWarning(
                    "[WorldProxy][DB-GATE] Rejected before protocol rewrite. AccountId={AccountId}, Reason={Reason}",
                    account.AccountId,
                    dbGateResult.FailureReason);
                return null;
            }

            byte[] digest = AcoreAuthSessionBuilder.BuildAcoreDigest(
                account.AccountName,
                retailFrame.LocalChallenge4,
                authSeed,
                account.SessionKey,
                Sha1ZeroPrefix,
                AcoreDigestBytes);

            byte[] addonInfo = AcoreAuthSessionBuilder.BuildMinimalAddonInfoBlob();
            byte[] payload = AcoreAuthSessionBuilder.BuildAcoreAuthSessionPayload(
                effectiveRetailFrame,
                account.AccountName,
                digest,
                addonInfo,
                _options.AcoreClientBuild,
                _options.AcoreRealmId);
            byte[] frame = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeAuthSession, payload);
            var authCrypt = new AuthCrypt();
            authCrypt.Init(account.SessionKey);

            CryptographicOperations.ZeroMemory(digest);
            return new AcoreAuthSessionBridgeResult(frame, authCrypt, account.SessionKey, account.BnetKeyData64, accountId, accountIdSource);
        }
        catch (Exception ex) when (ex is MySqlException or IOException or CryptographicException or InvalidOperationException)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][BRIDGE] Exception while building AC auth session frame.");
            bridgeState.SetEvidenceContext("DB", "db parity gate");
            bridgeState.MarkTemporalInvariant(
                name: "db_parity_gate",
                passed: false,
                expected: "DB parity gate should pass without runtime exceptions.",
                actual: ex.GetType().Name);
            return null;
        }
    }

    private async ValueTask<(int AccountId, string Source)> ResolveMissingRetailAccountIdAsync(CancellationToken cancellationToken)
    {
        if (_options.AuthAccountIdFallback > 0)
        {
            return (_options.AuthAccountIdFallback, "config:AuthAccountIdFallback");
        }

        int? latestAccountId = await _worldSessionMaterialRepository.TryReadLatestSessionMaterialAccountIdAsync(cancellationToken).ConfigureAwait(false);
        if (latestAccountId is > 0)
        {
            return (latestAccountId.Value, "db:adapter_world_session_material.latest");
        }

        return (0, "none");
    }

    private static bool TryBuildRetailAuthResponseFromAcore(
        ReadOnlySpan<byte> acPayload,
        bool probeResultOnly,
        uint probeResultOnlyCode,
        bool probeMinimalSuccessNoAccountData,
        bool probeTwwAccountDataProfile,
        bool probeTwwAddResultPrefix,
        bool probeForceWaitInfoPresent,
        bool probeForceCurrentBuildPresent,
        int probeAuthResponseAvailableClassesCardinality,
        int probeAuthResponseTwwClassMatrixRows,
        bool probeAuthResponseTwwUseAcoreExpansionLevels,
        AuthResponseFuzzMutation authResponseFuzzMutation,
        uint retailAuthResponseOpcode,
        uint acoreRealmId,
        out byte[] retailFrame,
        out string? error)
    {
        retailFrame = Array.Empty<byte>();
        error = null;

        if (acPayload.IsEmpty)
        {
            error = "Acore SMSG_AUTH_RESPONSE payload is empty.";
            return false;
        }

        if (probeResultOnly)
        {
            // M1-PROBE-067 isolation: send bare minimum AUTH_RESPONSE body to separate
            // crypto-framing faults from account-data schema faults.
            var resultOnlyPayload = new BitPackedBufferWriter(initialCapacity: 8);
            resultOnlyPayload.WriteUInt32LE(probeResultOnlyCode);
            retailFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(retailAuthResponseOpcode, resultOnlyPayload.WrittenSpan);
            return true;
        }

        if (probeTwwAccountDataProfile)
        {
            retailFrame = BuildRetailAuthResponseTwwAccountDataProbeFrame(
                acPayload,
                acoreRealmId,
                retailAuthResponseOpcode,
                probeTwwAddResultPrefix,
                probeAuthResponseAvailableClassesCardinality,
                probeAuthResponseTwwClassMatrixRows,
                probeAuthResponseTwwUseAcoreExpansionLevels,
                authResponseFuzzMutation);
            return true;
        }

        const byte AuthOk = 0x0C;
        const byte AuthWaitQueue = 0x1B;
        const byte WotlkExpansion = 2;

        byte acResult = acPayload[0];
        bool isAuthOk = acResult == AuthOk || probeMinimalSuccessNoAccountData;
        bool isWaitQueue = !probeMinimalSuccessNoAccountData && acResult == AuthWaitQueue;
        bool hasSuccessInfo = !probeMinimalSuccessNoAccountData && (isAuthOk || isWaitQueue);
        // Match Trinity behavior: WaitInfo is present only for queued logins.
        bool hasWaitInfo = !probeMinimalSuccessNoAccountData && isWaitQueue;
        if (probeForceWaitInfoPresent && hasSuccessInfo)
        {
            hasWaitInfo = true;
        }

        uint retailResult = hasSuccessInfo
            ? 0u // ERROR_OK
            : 3u; // ERROR_DENIED

        var payload = new BitPackedBufferWriter(initialCapacity: 128);
        payload.WriteUInt32LE(retailResult);

        payload.WriteBit(hasSuccessInfo);
        payload.WriteBit(hasWaitInfo);
        payload.FlushBits();

        uint billingTimeRemaining = acPayload.Length >= 5 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(1, 4)) : 0u;
        uint billingTimeRested = acPayload.Length >= 10 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(6, 4)) : 0u;
        byte accountExpansion = acPayload.Length >= 11
            ? (byte)Math.Clamp(acPayload[10], (byte)0, WotlkExpansion)
            : WotlkExpansion;
        if (accountExpansion == 0)
        {
            accountExpansion = WotlkExpansion;
        }

        uint waitCount = acPayload.Length >= 15 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(11, 4)) : 0u;
        bool hasFcm = acPayload.Length >= 16 && acPayload[15] != 0;

        if (hasSuccessInfo)
        {
            // AuthSuccessInfo (TrinityCore serialization order)
            uint virtualRealmAddress = 0x0101_0001; // Region=1, Battlegroup=1, Realm=1
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            payload.WriteUInt32LE(virtualRealmAddress); // VirtualRealmAddress
            payload.WriteUInt32LE(1); // VirtualRealms count
            payload.WriteUInt32LE(billingTimeRested); // TimeRested
            payload.WriteByte(accountExpansion); // ActiveExpansionLevel
            payload.WriteByte(accountExpansion); // AccountExpansionLevel
            payload.WriteUInt32LE(0); // TimeSecondsUntilPCKick
            payload.WriteUInt32LE(1); // AvailableClasses count
            payload.WriteUInt32LE(0); // Templates count
            payload.WriteUInt32LE(0); // CurrencyID
            payload.WriteInt64LE(now); // Time (Timestamp<int64>)

            // Minimal race/class availability set (Human/Warrior) for client bootstrap.
            payload.WriteByte(1); // RaceID
            payload.WriteUInt32LE(1); // Classes count
            payload.WriteByte(1); // ClassID
            payload.WriteByte(accountExpansion); // ActiveExpansionLevel
            payload.WriteByte(accountExpansion); // AccountExpansionLevel
            payload.WriteByte(0); // MinActiveExpansionLevel

            // Optional bits in AuthSuccessInfo
            bool currentBuildPresent = probeForceCurrentBuildPresent;
            payload.WriteBit(false); // IsExpansionTrial
            payload.WriteBit(false); // ForceCharacterTemplate
            payload.WriteBit(false); // NumPlayersHorde
            payload.WriteBit(false); // NumPlayersAlliance
            payload.WriteBit(false); // ExpansionTrialExpiration
            payload.WriteBit(currentBuildPresent); // CurrentBuild
            payload.FlushBits();

            if (currentBuildPresent)
            {
                payload.WriteUInt32LE(AuthResponseReplayCurrentBuildValue); // Retail build for CurrentBuild optional field probe.
            }

            // GameTime
            payload.WriteUInt32LE(0); // BillingType
            payload.WriteUInt32LE(billingTimeRemaining); // MinutesRemaining (best-effort mapping)
            payload.WriteUInt32LE(0); // RealBillingType
            payload.WriteBit(false); // IsInIGR
            payload.WriteBit(false); // IsPaidForByIGR
            payload.WriteBit(false); // IsCAISEnabled
            payload.FlushBits();

            // Single VirtualRealmInfo
            const string realmName = "AzerothCore";
            payload.WriteUInt32LE(virtualRealmAddress);
            payload.WriteBit(true);  // IsLocal
            payload.WriteBit(false); // IsInternalRealm
            payload.WriteBits((ulong)realmName.Length, 8); // RealmNameActual length
            payload.WriteBits((ulong)realmName.Length, 8); // RealmNameNormalized length
            payload.FlushBits();
            payload.WriteAscii(realmName);
            payload.WriteAscii(realmName);
        }

        if (hasWaitInfo)
        {
            payload.WriteUInt32LE(waitCount); // WaitCount
            payload.WriteUInt32LE(0); // WaitTime
            payload.WriteByte(0); // AllowedFactionGroupForCharacterCreate
            payload.WriteBit(hasFcm); // HasFCM
            payload.WriteBit(false); // CanCreateOnlyIfExisting
            payload.FlushBits();
        }

        retailFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(retailAuthResponseOpcode, payload.WrittenSpan);
        return true;
    }

    private static byte[] BuildRetailAuthResponseTwwAccountDataProbeFrame(
        ReadOnlySpan<byte> acPayload,
        uint acoreRealmId,
        uint retailAuthResponseOpcode,
        bool includeResultPrefix,
        int availableClassesCardinality,
        int trinityClassMatrixRows,
        bool useAcoreExpansionLevels,
        AuthResponseFuzzMutation authResponseFuzzMutation)
    {
        uint billingTimeRemaining = acPayload.Length >= 5 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(1, 4)) : 0u;
        uint billingTimeRested = acPayload.Length >= 10 ? BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(6, 4)) : 0u;
        uint realmId = acoreRealmId != 0 ? acoreRealmId : 1u;
        uint virtualRealmAddress = (1u << 24) | (1u << 16) | (realmId & 0xFFFF);
        const byte ExpansionTww = 10;
        const byte ExpansionWotlk = 2;
        const string RealmName = "AIMAYA";
        long nowUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte topExpansionLevel = ExpansionTww;
        if (useAcoreExpansionLevels)
        {
            byte acoreExpansion = acPayload.Length >= 11
                ? (byte)Math.Clamp(acPayload[10], (byte)0, ExpansionTww)
                : ExpansionWotlk;
            if (acoreExpansion == 0)
            {
                acoreExpansion = ExpansionWotlk;
            }

            topExpansionLevel = acoreExpansion;
        }

        // TWW probe profile aligned to Trinity AuthResponse envelope:
        // Result(uint32) + Optional(SuccessInfo/WaitInfo) bits + FlushBits + SuccessInfo payload.
        var payload = new BitPackedBufferWriter(initialCapacity: 192);
        if (includeResultPrefix)
        {
            payload.WriteUInt32LE(0); // Legacy probe knob; disabled for strict profile runs.
        }

        payload.WriteUInt32LE(0); // ERROR_OK

        if (authResponseFuzzMutation.Enabled && authResponseFuzzMutation.LeadingZeroBits > 0)
        {
            for (int bit = 0; bit < authResponseFuzzMutation.LeadingZeroBits; bit++)
            {
                payload.WriteBit(false);
            }
        }

        payload.WriteBit(true);  // SuccessInfo present
        payload.WriteBit(false); // WaitInfo absent
        payload.FlushBits();

        if (authResponseFuzzMutation.Enabled && authResponseFuzzMutation.InsertPaddingU32AfterBitBlock)
        {
            payload.WriteUInt32LE(0);
        }

        // AuthSuccessInfo (serialization order mirrors TrinityCore master branch)
        List<(byte RaceId, byte[] ClassIds)> raceClassMatrix;
        if (trinityClassMatrixRows > 0)
        {
            raceClassMatrix = AuthResponseClassMatrixHelpers.BuildLegacyClassMatrixPrefix(trinityClassMatrixRows);
        }
        else
        {
            int normalizedCardinality = Math.Clamp(availableClassesCardinality, 1, 13);
            byte[] twwClassIds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
            raceClassMatrix = new List<(byte RaceId, byte[] ClassIds)>(1)
            {
                ((byte)1, twwClassIds.AsSpan(0, normalizedCardinality).ToArray())
            };
        }

        payload.WriteUInt32LE(virtualRealmAddress); // VirtualRealmAddress
        payload.WriteUInt32LE(1); // VirtualRealms size
        payload.WriteUInt32LE(billingTimeRested); // TimeRested
        payload.WriteByte(topExpansionLevel); // ActiveExpansionLevel
        payload.WriteByte(topExpansionLevel); // AccountExpansionLevel
        payload.WriteUInt32LE(0); // TimeSecondsUntilPCKick
        payload.WriteUInt32LE((uint)raceClassMatrix.Count); // AvailableClasses size
        payload.WriteUInt32LE(0); // Templates size
        payload.WriteUInt32LE(0); // CurrencyID
        payload.WriteInt64LE(nowUnixSeconds); // Time

        for (int raceIndex = 0; raceIndex < raceClassMatrix.Count; raceIndex++)
        {
            (byte raceId, byte[] classIds) = raceClassMatrix[raceIndex];
            payload.WriteByte(raceId);
            payload.WriteUInt32LE((uint)classIds.Length);
            for (int classIndex = 0; classIndex < classIds.Length; classIndex++)
            {
                byte classId = classIds[classIndex];
                payload.WriteByte(classId);
                if (trinityClassMatrixRows > 0)
                {
                    (byte activeExpansion, byte accountExpansion, byte minActiveExpansion) =
                        AuthResponseClassMatrixHelpers.GetLegacyClassExpansionRequirement(classId);
                    payload.WriteByte(activeExpansion);
                    payload.WriteByte(accountExpansion);
                    payload.WriteByte(minActiveExpansion);
                }
                else
                {
                    payload.WriteByte(ExpansionTww); // ActiveExpansionLevel
                    payload.WriteByte(ExpansionTww); // AccountExpansionLevel
                    payload.WriteByte(0); // MinActiveExpansionLevel
                }
            }
        }

        // SuccessInfo optional flags
        payload.WriteBit(false); // IsExpansionTrial
        payload.WriteBit(false); // ForceCharacterTemplate
        payload.WriteBit(false); // NumPlayersHorde present
        payload.WriteBit(false); // NumPlayersAlliance present
        payload.WriteBit(false); // ExpansionTrialExpiration present
        payload.WriteBit(false); // CurrentBuild present
        payload.FlushBits();

        // GameTimeInfo
        payload.WriteUInt32LE(0); // BillingType
        payload.WriteUInt32LE(billingTimeRemaining); // MinutesRemaining
        payload.WriteUInt32LE(0); // RealBillingType
        payload.WriteBit(false); // IsInIGR
        payload.WriteBit(false); // IsPaidForByIGR
        payload.WriteBit(false); // IsCAISEnabled
        payload.FlushBits();

        // VirtualRealmInfo (single entry)
        payload.WriteUInt32LE(virtualRealmAddress); // RealmAddress
        payload.WriteBit(true);  // IsLocal
        payload.WriteBit(false); // IsInternalRealm
        payload.WriteBits((ulong)RealmName.Length, 8); // RealmNameActual length
        payload.WriteBits((ulong)RealmName.Length, 8); // RealmNameNormalized length
        payload.FlushBits();
        payload.WriteAscii(RealmName); // RealmNameActual
        payload.WriteAscii(RealmName); // RealmNameNormalized

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(retailAuthResponseOpcode, payload.WrittenSpan);
    }

    private static byte[] BuildRetailAuthSequencePreludeFrame(ReadOnlySpan<byte> payloadBytes)
    {
        if (payloadBytes.Length != 4)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadBytes), "Retail prelude payload must be exactly 4 bytes.");
        }

        Span<byte> payload = stackalloc byte[4];
        payloadBytes.CopyTo(payload);
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAuthSequencePrelude, payload);
    }

    private static byte[] BuildRetailSetTimeZoneInformationFrame()
    {
        const string timezone = "Etc/UTC";

        var payload = new BitPackedBufferWriter(initialCapacity: 48);
        payload.WriteBits((ulong)timezone.Length, 7);
        payload.WriteBits((ulong)timezone.Length, 7);
        payload.WriteBits((ulong)timezone.Length, 7);
        payload.FlushBits();

        payload.WriteAscii(timezone);
        payload.WriteAscii(timezone);
        payload.WriteAscii(timezone);

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgSetTimeZoneInformation, payload.WrittenSpan);
    }

    private static byte[] BuildRetailFeatureSystemStatusGlueScreenFrame(bool trinitySemantics = false)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: trinitySemantics ? 224 : 160);

        // First 16 bits
        payload.WriteBit(false); // BpayStoreAvailable
        payload.WriteBit(false); // CharUndeleteEnabled
        payload.WriteBit(false); // CommerceServerEnabled
        payload.WriteBit(false); // PaidCharacterTransfersBetweenBnetAccountsEnabled
        payload.WriteBit(false); // VeteranTokenRedeemWillKick
        payload.WriteBit(false); // WorldTokenRedeemWillKick
        payload.WriteBit(false); // ExpansionPreorderInStore
        payload.WriteBit(false); // KioskModeEnabled
        payload.WriteBit(false); // CompetitiveModeEnabled
        payload.WriteBit(false); // BoostEnabled
        payload.WriteBit(false); // TrialBoostEnabled
        payload.WriteBit(false); // RedeemForBalanceAvailable
        payload.WriteBit(false); // LiveRegionCharacterListEnabled
        payload.WriteBit(false); // LiveRegionCharacterCopyEnabled
        payload.WriteBit(false); // LiveRegionAccountCopyEnabled
        payload.WriteBit(false); // LiveRegionKeyBindingsCopyEnabled

        // Next flag block
        payload.WriteBit(false); // BrowserCrashReporterEnabled
        payload.WriteBit(false); // IsEmployeeAccount
        payload.WriteBit(trinitySemantics); // Optional EuropaTicketSystemStatus
        payload.WriteBit(false); // NameReservationOnly
        payload.WriteBit(false); // Optional LaunchDurationETA
        payload.WriteBit(false); // TimerunningEnabled
        payload.WriteBit(false); // ScriptsDisallowedForBeta
        payload.WriteBit(false); // PlayerIdentityOptionsEnabled
        payload.WriteBit(false); // AccountExportEnabled
        payload.WriteBit(false); // AccountLockedPostExport
        payload.WriteBits(0, 11); // RealmHiddenAlert sized c-string bits size
        payload.WriteBit(trinitySemantics); // BNSendWhisperUseV2Services
        payload.WriteBit(trinitySemantics); // BNSendGameDataUseV2Services
        payload.WriteBit(false); // CharacterSelectListModeRealmless
        payload.WriteBit(false); // WowTokenLimitedMode
        payload.WriteBit(false); // NavBarEnabled
        payload.WriteBit(false); // GlobalUserGeneratedContentMuteEnabled
        payload.WriteBit(false); // AccountUserGeneratedContentIsRisky
        payload.FlushBits();

        if (trinitySemantics)
        {
            // Trinity writes EuropaTicketConfig immediately after the bit block when present.
            payload.WriteBit(false); // TicketsEnabled
            payload.WriteBit(false); // BugsEnabled
            payload.WriteBit(false); // ComplaintsEnabled
            payload.WriteBit(false); // SuggestionsEnabled
            payload.FlushBits();

            payload.WriteUInt32LE(10); // ThrottleState.MaxTries
            payload.WriteUInt32LE(60000); // ThrottleState.PerMilliseconds
            payload.WriteUInt32LE(1); // ThrottleState.TryCount
            payload.WriteUInt32LE(111111); // ThrottleState.LastResetTimeBeforeNow

            payload.WriteUInt32LE(0); // ExpensiveThrottleState.MaxTries
            payload.WriteUInt32LE(0); // ExpensiveThrottleState.PerMilliseconds
            payload.WriteUInt32LE(0); // ExpensiveThrottleState.TryCount
            payload.WriteUInt32LE(0); // ExpensiveThrottleState.LastResetTimeBeforeNow
        }

        payload.WriteUInt32LE(0); // CommercePricePollTimeSeconds
        payload.WriteUInt32LE(0); // KioskSessionDurationMinutes
        payload.WriteInt64LE(0); // RedeemForBalanceAmount
        payload.WriteInt32LE(50); // MaxCharactersOnThisRealm
        payload.WriteUInt32LE(0); // LiveRegionCharacterCopySourceRegions size
        payload.WriteInt32LE(0); // ActiveBoostType
        payload.WriteInt32LE(0); // TrialBoostType
        payload.WriteInt32LE(0); // MinimumExpansionLevel
        payload.WriteInt32LE(2); // MaximumExpansionLevel
        payload.WriteInt32LE(0); // ContentSetID
        payload.WriteUInt32LE(0); // DisabledGameModes size
        payload.WriteUInt32LE(0); // GameRules size
        payload.WriteUInt32LE(1); // AvailableGameModeIDs size
        payload.WriteInt32LE(0); // ActiveTimerunningSeasonID
        payload.WriteInt32LE(0); // RemainingTimerunningSeasonSeconds
        payload.WriteInt32LE(86400); // TimerunningConversionMinCharacterAge
        payload.WriteInt32LE(-1); // TimerunningConversionMaxSeasonID
        payload.WriteInt16LE(50); // MaxPlayerGuidLookupsPerRequest
        payload.WriteInt16LE(600); // NameLookupTelemetryInterval
        payload.WriteUInt32LE(10); // NotFoundCacheTimeSeconds
        payload.WriteUInt32LE(0); // DebugTimeEvents size
        payload.WriteInt32LE(0); // MostRecentTimeEventID
        payload.WriteUInt32LE(0); // EventRealmQueues
        payload.WriteInt32LE(8); // AvailableGameModeIDs[0]

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgFeatureSystemStatusGlueScreen, payload.WrittenSpan);
    }

    private static byte[] BuildRetailEmptyEnumCharactersResultFrame()
    {
        // Trinity 12.x EnumCharactersResult layout for empty list.
        // Controlled unlock variant uses permissive unlock metadata to keep character creation UI enabled.
        // This path is used only for AC empty char-list payloads under explicit config flag.
        var payload = new BitPackedBufferWriter(initialCapacity: 320);
        ReadOnlySpan<byte> unlockedRaces =
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 37
        ];

        payload.WriteBit(true);  // Success
        payload.WriteBit(false); // Realmless
        payload.WriteBit(false); // IsDeletedCharacters
        payload.WriteBit(true);  // IgnoreNewPlayerRestrictions
        payload.WriteBit(false); // IsRestrictedNewPlayer
        payload.WriteBit(true);  // IsNewcomerChatCompleted
        payload.WriteBit(false); // IsRestrictedTrial
        payload.WriteBit(false); // IsAccountLapsedPlayer
        payload.WriteBit(true);  // ClassDisableMask present (Trinity initializes Optional<uint32>)
        payload.WriteBit(false); // ForceCharacterListSort
        payload.FlushBits();

        payload.WriteUInt32LE(0); // Characters size
        payload.WriteUInt32LE(0); // RegionwideCharacters size
        payload.WriteInt32LE(80); // MaxCharacterLevel
        payload.WriteUInt32LE((uint)unlockedRaces.Length); // RaceUnlockData size
        payload.WriteUInt32LE(0); // UnlockedConditionalAppearances size
        payload.WriteUInt32LE(0); // RaceLimitDisables size
        payload.WriteUInt32LE(0); // WarbandGroups size
        payload.WriteUInt32LE(0); // ClassDisableMask value

        for (int i = 0; i < unlockedRaces.Length; i++)
        {
            payload.WriteByte(unlockedRaces[i]); // RaceID
            payload.WriteUInt32LE(1); // ClassUnlocks size
            payload.WriteBit(true);   // HasUnlockedLicense
            payload.WriteBit(true);   // HasUnlockedAchievement
            payload.WriteBit(false);  // HasHeritageArmorUnlockAchievement
            payload.WriteBit(false);  // HideRaceOnClient
            payload.WriteBit(false);  // FactionBalanceDisabled
            payload.FlushBits();

            payload.WriteByte(1);     // ClassID (Warrior)
            payload.WriteUInt32LE(0); // AchievementID
            payload.WriteBit(true);   // HasUnlockedAchievement
            payload.FlushBits();
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgEnumCharactersResult, payload.WrittenSpan);
    }

    private static byte[] BuildRetailMirrorVarsFrame()
    {
        (string Name, string Value)[] vars =
        [
            ("raidLockoutExtendEnabled", "1"),
            ("bypassItemLevelScalingCode", "0"),
            ("shop2Enabled", "0"),
            ("bpayStoreEnable", "0"),
            ("recentAlliesEnabledClient", "0"),
            ("browserEnabled", "0"),
            ("housingEnableCreateGuildNeighborhood", "0"),
            ("housingEnableDeleteHouse", "0"),
            ("housingServiceEnabled", "0"),
            ("housingEnableMoveHouse", "0"),
            ("housingEnableCreateCharterNeighborhood", "0"),
            ("housingEnableBuyHouse", "0"),
            ("housingMarketEnabled", "0")
        ];

        var payload = new BitPackedBufferWriter(initialCapacity: 384);
        payload.WriteUInt32LE((uint)vars.Length);
        for (int i = 0; i < vars.Length; i++)
        {
            payload.WriteBit(false); // UpdateType
            payload.WriteBits((ulong)vars[i].Name.Length, 24);
            payload.WriteBits((ulong)vars[i].Value.Length, 24);
            payload.FlushBits();
            payload.WriteAscii(vars[i].Name);
            payload.WriteAscii(vars[i].Value);
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgMirrorVars, payload.WrittenSpan);
    }

    private static uint BuildRetailVirtualRealmAddress(uint acoreRealmId)
    {
        uint realmId = acoreRealmId != 0 ? acoreRealmId : 1u;
        return (1u << 24) | (1u << 16) | (realmId & 0xFFFF);
    }

    private static byte[] BuildRetailCacheVersionFrame(byte[]? acoreCacheVersionPayload)
    {
        ReadOnlySpan<byte> payload = acoreCacheVersionPayload is { Length: 4 }
            ? acoreCacheVersionPayload
            : [0, 0, 0, 0];
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgCacheVersion, payload);
    }

    private static byte[] BuildRetailAvailableHotfixesFrame(uint acoreRealmId)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 8);
        payload.WriteInt32LE(unchecked((int)BuildRetailVirtualRealmAddress(acoreRealmId))); // VirtualRealmAddress
        payload.WriteUInt32LE(0); // Hotfixes count
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAvailableHotfixes, payload.WrittenSpan);
    }

    private static byte[] BuildRetailAccountDataTimesFrame()
    {
        // Trinity serialization:
        // packed ObjectGuid (empty => two zero mask bytes) + int64 server time + 20x int64 account timestamps.
        var payload = new BitPackedBufferWriter(initialCapacity: 2 + 8 + (RetailAccountDataTimesCount * 8));
        payload.WriteByte(0); // ObjectGuid mask[0] for ObjectGuid::Empty
        payload.WriteByte(0); // ObjectGuid mask[1] for ObjectGuid::Empty
        payload.WriteInt64LE(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); // ServerTime
        for (int i = 0; i < RetailAccountDataTimesCount; i++)
        {
            payload.WriteInt64LE(0); // AccountTimes[i]
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAccountDataTimes, payload.WrittenSpan);
    }

    private static byte[] BuildRetailTutorialFlagsFrame(byte[]? acoreTutorialFlagsPayload)
    {
        ReadOnlySpan<byte> payload = acoreTutorialFlagsPayload is { Length: RetailTutorialValuesCount * sizeof(uint) }
            ? acoreTutorialFlagsPayload
            : new byte[RetailTutorialValuesCount * sizeof(uint)];
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTutorialFlags, payload);
    }

    private static byte[] BuildRetailBattleNetConnectionStatusFrame(byte state, bool suppressNotification)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 1);
        payload.WriteBits((ulong)(state & 0x03), 2); // State
        payload.WriteBit(suppressNotification); // SuppressNotification
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgBattleNetConnectionStatus, payload.WrittenSpan);
    }

    private static byte[] BuildRetailAccountItemCollectionDataFrame()
    {
        // Trinity 12.x CollectionPackets::AccountItemCollectionData::Write
        // with empty warband-scene collection.
        var payload = new BitPackedBufferWriter(initialCapacity: 10);
        payload.WriteUInt32LE(0); // Unknown1110_1
        payload.WriteByte(7); // Type = ItemCollectionType::WarbandScene
        payload.WriteUInt32LE(0); // Items count
        payload.WriteBit(false); // Unknown1110_2
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAccountItemCollectionData, payload.WrittenSpan);
    }

    private static byte[] BuildRetailSocialContractRequestResponseFrame(bool showSocialContract)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 1);
        payload.WriteBit(showSocialContract);
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgSocialContractRequestResponse, payload.WrittenSpan);
    }

    private static byte[] BuildRetailUndeleteCooldownStatusResponseFrame(
        uint maxCooldownSeconds,
        uint currentCooldownSeconds,
        bool onCooldown)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 9);
        payload.WriteUInt32LE(maxCooldownSeconds);
        payload.WriteUInt32LE(currentCooldownSeconds);
        payload.WriteBit(onCooldown);
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgUndeleteCooldownStatusResponse, payload.WrittenSpan);
    }

    private static byte[] BuildRetailDbReplyFrame(
        uint tableHash,
        int recordId,
        uint timestamp,
        byte status,
        ReadOnlySpan<byte> data)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 20 + data.Length);
        payload.WriteUInt32LE(tableHash);
        payload.WriteInt32LE(recordId);
        payload.WriteUInt32LE(timestamp);
        payload.WriteBits((ulong)(status & 0x07), 3); // DB2Manager::HotfixRecord::Status (3 bits)
        payload.WriteUInt32LE((uint)data.Length);
        if (!data.IsEmpty)
        {
            payload.WriteBytes(data);
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgDbReply, payload.WrittenSpan);
    }

    private static byte[] BuildRetailBattleNetResponseFrame(
        ulong methodType,
        ulong objectId,
        uint token,
        uint statusCode,
        ReadOnlySpan<byte> data)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 28 + data.Length);
        payload.WriteUInt32LE(statusCode);
        payload.WriteUInt64LE(methodType);
        payload.WriteUInt64LE(objectId);
        payload.WriteUInt32LE(token);
        payload.WriteUInt32LE((uint)data.Length);
        if (!data.IsEmpty)
        {
            payload.WriteBytes(data);
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgBattleNetResponse, payload.WrittenSpan);
    }

    private static byte[] BuildRetailServerTimeOffsetFrame(long unixTimeSeconds)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: sizeof(long));
        payload.WriteInt64LE(unixTimeSeconds);
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgServerTimeOffset, payload.WrittenSpan);
    }

    private static byte[] BuildRetailHotfixConnectFrame()
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 8);
        payload.WriteUInt32LE(0); // Hotfixes count
        payload.WriteUInt32LE(0); // HotfixContent size
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgHotfixConnect, payload.WrittenSpan);
    }

    private static bool TryDecodeAzerothAuthChallenge(ReadOnlySequence<byte> buffer, out AcoreAuthChallengeDump dump)
    {
        dump = default;
        // AC world challenge packet: 2-byte size + 2-byte opcode + 40-byte payload.
        if (buffer.Length < 44)
        {
            return false;
        }

        Span<byte> frame = stackalloc byte[44];
        buffer.Slice(0, 44).CopyTo(frame);

        uint dosChallenge = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(4, 4));
        uint authSeed = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(8, 4));
        byte[] newSeed = GC.AllocateUninitializedArray<byte>(32);
        frame.Slice(12, 32).CopyTo(newSeed);
        string newSeedHex = Convert.ToHexString(newSeed);

        dump = new AcoreAuthChallengeDump(dosChallenge, authSeed, newSeedHex, newSeed);
        return true;
    }

    private static async ValueTask CompletePipeSafelyAsync(PipeReader reader)
    {
        try
        {
            await reader.CompleteAsync().ConfigureAwait(false);
        }
        catch
        {
            // Ignore complete errors during teardown.
        }
    }

    private static async ValueTask CompletePipeSafelyAsync(PipeWriter writer)
    {
        try
        {
            await writer.CompleteAsync().ConfigureAwait(false);
        }
        catch
        {
            // Ignore complete errors during teardown.
        }
    }

    private sealed class RetailPostAuthClientTranslator
    {
        private const int RetailOuterHeaderBytes = 16;
        private const int RetailHeaderBytes = 20;
        private const int MaxRetailFrameBytes = 4 * 1024 * 1024;
        private const int MaxDbQueryBulkRecords = 4096;

        private readonly AuthCrypt _authCrypt;
        private readonly WorldProxyBridgeState _bridgeState;
        private readonly bool _strictStageEnforcement;
        private readonly byte[] _sizePrefix = new byte[4];
        private readonly HashSet<uint> _loggedDroppedOpcodes = new();
        private readonly Action<uint>? _onLogDisconnect;
        private readonly Action? _onEnumCharactersRequest;
        private readonly Action? _onEnterEncryptedModeAck;
        private readonly Action<uint>? _onPostAckNonAckClientFrame;
        private readonly int _glueSyntheticCharEnumKickMinIntervalMs;
        private readonly Action<uint, int>? _onGlueSyntheticKickSuppressed;

        private int _sizePrefixRead;
        private byte[] _frameBuffer = Array.Empty<byte>();
        private int _frameBytesRead;
        private int _frameExpectedBytes;
        private long _lastGlueSyntheticKickUnixMs = long.MinValue;

        public RetailPostAuthClientTranslator(
            AuthCrypt authCrypt,
            WorldProxyBridgeState bridgeState,
            bool strictStageEnforcement = true,
            Action<uint>? onLogDisconnect = null,
            Action? onEnumCharactersRequest = null,
            Action? onEnterEncryptedModeAck = null,
            Action<uint>? onPostAckNonAckClientFrame = null,
            int glueSyntheticCharEnumKickMinIntervalMs = 0,
            Action<uint, int>? onGlueSyntheticKickSuppressed = null)
        {
            _authCrypt = authCrypt ?? throw new ArgumentNullException(nameof(authCrypt));
            _bridgeState = bridgeState ?? throw new ArgumentNullException(nameof(bridgeState));
            _strictStageEnforcement = strictStageEnforcement;
            _onLogDisconnect = onLogDisconnect;
            _onEnumCharactersRequest = onEnumCharactersRequest;
            _onEnterEncryptedModeAck = onEnterEncryptedModeAck;
            _onPostAckNonAckClientFrame = onPostAckNonAckClientFrame;
            _glueSyntheticCharEnumKickMinIntervalMs = Math.Clamp(glueSyntheticCharEnumKickMinIntervalMs, 0, 5000);
            _onGlueSyntheticKickSuppressed = onGlueSyntheticKickSuppressed;
        }

        public bool TryTransform(
            ReadOnlySequence<byte> input,
            IBufferWriter<byte> output,
            Action<uint, int>? onDroppedOpcode,
            out long bytesWritten,
            out string? error)
        {
            bytesWritten = 0;
            error = null;

            foreach (ReadOnlyMemory<byte> segment in input)
            {
                ReadOnlySpan<byte> span = segment.Span;
                int offset = 0;
                while (offset < span.Length)
                {
                    if (_frameExpectedBytes == 0)
                    {
                        int needPrefix = 4 - _sizePrefixRead;
                        int takePrefix = Math.Min(needPrefix, span.Length - offset);
                        span.Slice(offset, takePrefix).CopyTo(_sizePrefix.AsSpan(_sizePrefixRead, takePrefix));
                        _sizePrefixRead += takePrefix;
                        offset += takePrefix;

                        if (_sizePrefixRead < 4)
                        {
                            continue;
                        }

                        uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(_sizePrefix);
                        if (packetSize < 4)
                        {
                            error = $"Invalid Retail frame size field (<4): {packetSize}.";
                            return false;
                        }

                        _frameExpectedBytes = checked((int)packetSize + RetailOuterHeaderBytes);
                        if (_frameExpectedBytes < RetailHeaderBytes || _frameExpectedBytes > MaxRetailFrameBytes)
                        {
                            error = $"Invalid Retail frame size (bytes): {_frameExpectedBytes}.";
                            return false;
                        }

                        if (_frameBuffer.Length < _frameExpectedBytes)
                        {
                            _frameBuffer = GC.AllocateUninitializedArray<byte>(_frameExpectedBytes);
                        }

                        _sizePrefix.AsSpan().CopyTo(_frameBuffer.AsSpan(0, 4));
                        _frameBytesRead = 4;
                        _sizePrefixRead = 0;
                    }

                    int remaining = _frameExpectedBytes - _frameBytesRead;
                    int take = Math.Min(remaining, span.Length - offset);
                    span.Slice(offset, take).CopyTo(_frameBuffer.AsSpan(_frameBytesRead, take));
                    _frameBytesRead += take;
                    offset += take;

                    if (_frameBytesRead < _frameExpectedBytes)
                    {
                        continue;
                    }

                    if (!TryTranslateFrame(_frameBuffer.AsSpan(0, _frameExpectedBytes), output, onDroppedOpcode, out long frameBytes, out error))
                    {
                        return false;
                    }

                    bytesWritten += frameBytes;
                    _frameExpectedBytes = 0;
                    _frameBytesRead = 0;
                }
            }

            return true;
        }

        private bool TryTranslateFrame(
            ReadOnlySpan<byte> retailFrame,
            IBufferWriter<byte> output,
            Action<uint, int>? onDroppedOpcode,
            out long bytesWritten,
            out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (retailFrame.Length < RetailHeaderBytes)
            {
                error = $"Retail frame is too short: {retailFrame.Length}.";
                return false;
            }

            if (!_bridgeState.TryDecryptRetailClientFrame(retailFrame, out byte[] decryptedFrame, out string? decryptError))
            {
                error = $"Failed to decode Retail client world frame: {decryptError ?? "<unknown>"}";
                return false;
            }

            ReadOnlySpan<byte> effectiveFrame = decryptedFrame;

            uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(effectiveFrame[..4]);
            int expectedFrameBytes = checked((int)packetSize + RetailOuterHeaderBytes);
            if (effectiveFrame.Length != expectedFrameBytes || packetSize < 4)
            {
                error = $"Retail frame size mismatch. PacketSize={packetSize}, FrameBytes={effectiveFrame.Length}, Expected={expectedFrameBytes}.";
                return false;
            }

            uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(effectiveFrame.Slice(16, 4));
            int payloadBytes = (int)packetSize - 4;
            ReadOnlySpan<byte> payload = effectiveFrame.Slice(20, payloadBytes);

            if (!_bridgeState.ValidateClientOpcode(opcode, _strictStageEnforcement, out string? stageError))
            {
                error = stageError;
                return false;
            }

            if (opcode != RetailOpcodeEnterEncryptedModeAck && _bridgeState.AckObserved)
            {
                _onPostAckNonAckClientFrame?.Invoke(opcode);
            }

            if (opcode == RetailOpcodePing)
            {
                if (payloadBytes < 8)
                {
                    error = $"Retail CMSG_PING payload too short: {payloadBytes}.";
                    return false;
                }

                byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodePing, payload[..8]);
                _authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
                output.Write(mapped);
                bytesWritten = mapped.Length;
                return true;
            }

            if (opcode == RetailOpcodeEnterEncryptedModeAck)
            {
                // Retail world stage ack for SMSG_ENTER_ENCRYPTED_MODE.
                // No AC equivalent in 3.3.5 bridge mode.
                _onEnterEncryptedModeAck?.Invoke();
                return true;
            }

            if (opcode == RetailOpcodeEnumCharacters)
            {
                _onEnumCharactersRequest?.Invoke();
                byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeCharEnum, ReadOnlySpan<byte>.Empty);
                _authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
                output.Write(mapped);
                bytesWritten = mapped.Length;
                return true;
            }

            if (opcode == RetailOpcodeWarden3Data)
            {
                byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeWardenData, payload);
                _authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
                output.Write(mapped);
                bytesWritten = mapped.Length;
                return true;
            }

            if (opcode == RetailOpcodeCmsgGetUndeleteCharacterCooldownStatus)
            {
                _bridgeState.MarkPendingUndeleteCooldownStatusRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgSocialContractRequest)
            {
                _bridgeState.MarkPendingSocialContractRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgDbQueryBulk)
            {
                if (TryParseRetailDbQueryBulk(payload, out ParsedDbQueryBulk query, out _))
                {
                    _bridgeState.EnqueuePendingDbQueryBulkReplies(query.TableHash, query.RecordIds);
                }
                else if (_loggedDroppedOpcodes.Add(opcode))
                {
                    onDroppedOpcode?.Invoke(opcode, payloadBytes);
                }

                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgHotfixRequest)
            {
                _bridgeState.MarkPendingHotfixRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgServerTimeOffsetRequest)
            {
                _bridgeState.MarkPendingServerTimeOffsetRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgBattlenetRequest)
            {
                if (TryParseRetailBattlenetRequest(payload, out ParsedBattlenetRequest request, out _))
                {
                    _bridgeState.EnqueuePendingBattleNetResponse(
                        request.MethodType,
                        request.ObjectId,
                        request.Token);
                }
                else if (_loggedDroppedOpcodes.Add(opcode))
                {
                    onDroppedOpcode?.Invoke(opcode, payloadBytes);
                }

                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgBattlePayGetPurchaseList ||
                opcode == RetailOpcodeCmsgBattlePayGetProductList ||
                opcode == RetailOpcodeCmsgUpdateVasPurchaseStates ||
                opcode == RetailOpcodeCmsgQuickJoinAutoAcceptRequests ||
                opcode == RetailOpcodeCmsgGetLastCatalogFetch)
            {
                if (_bridgeState.CurrentStage >= BridgeStage.CHAR_ENUM_RECEIVED)
                {
                    // After first char-enum is already delivered, these glue opcodes are noise
                    // (TC commonly ignores them). Do not trigger extra synthetic enum turns.
                    return true;
                }

                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == RetailOpcodeCmsgAddonList)
            {
                // AC receives addon metadata inside CMSG_AUTH_SESSION payload.
                // Ignore standalone Retail addon list packets in bridge mode.
                return true;
            }

            if (opcode == RetailOpcodeKeepAlive)
            {
                byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeKeepAlive, ReadOnlySpan<byte>.Empty);
                _authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
                output.Write(mapped);
                bytesWritten = mapped.Length;
                return true;
            }

            if (opcode == RetailOpcodeTimeSyncResponse)
            {
                if (payloadBytes < 8)
                {
                    error = $"Retail CMSG_TIME_SYNC_RESPONSE payload too short: {payloadBytes}.";
                    return false;
                }

                byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeTimeSyncResp, payload[..8]);
                _authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
                output.Write(mapped);
                bytesWritten = mapped.Length;
                return true;
            }

            if (opcode == RetailOpcodeLogDisconnect)
            {
                if (payloadBytes >= 4)
                {
                    _onLogDisconnect?.Invoke(BinaryPrimitives.ReadUInt32LittleEndian(payload[..4]));
                }

                // Client is terminating world session; nothing to forward to AC in 3.3.5 bridge mode.
                return true;
            }

            if (_loggedDroppedOpcodes.Add(opcode))
            {
                onDroppedOpcode?.Invoke(opcode, payloadBytes);
            }

            return true;
        }

        private bool ForwardSyntheticAcoreCharEnumRequest(IBufferWriter<byte> output, out long bytesWritten)
        {
            byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(AcoreOpcodeCharEnum, ReadOnlySpan<byte>.Empty);
            _authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
            output.Write(mapped);
            bytesWritten = mapped.Length;
            return true;
        }

        private bool TryKickGlueResponseTurn(IBufferWriter<byte> output, uint triggerOpcode, out long bytesWritten)
        {
            bytesWritten = 0;

            bool bypassThrottle = triggerOpcode == RetailOpcodeCmsgDbQueryBulk ||
                                  triggerOpcode == RetailOpcodeCmsgBattlenetRequest ||
                                  triggerOpcode == RetailOpcodeCmsgServerTimeOffsetRequest ||
                                  triggerOpcode == RetailOpcodeCmsgHotfixRequest ||
                                  triggerOpcode == RetailOpcodeCmsgBattlePayGetPurchaseList ||
                                  triggerOpcode == RetailOpcodeCmsgBattlePayGetProductList ||
                                  triggerOpcode == RetailOpcodeCmsgUpdateVasPurchaseStates ||
                                  triggerOpcode == RetailOpcodeCmsgQuickJoinAutoAcceptRequests ||
                                  triggerOpcode == RetailOpcodeCmsgGetLastCatalogFetch ||
                                  triggerOpcode == RetailOpcodeCmsgSocialContractRequest ||
                                  triggerOpcode == RetailOpcodeCmsgGetUndeleteCharacterCooldownStatus;

            if (!bypassThrottle &&
                _glueSyntheticCharEnumKickMinIntervalMs > 0 &&
                _lastGlueSyntheticKickUnixMs != long.MinValue)
            {
                long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                long elapsedMs = nowUnixMs - _lastGlueSyntheticKickUnixMs;
                if (elapsedMs >= 0 && elapsedMs < _glueSyntheticCharEnumKickMinIntervalMs)
                {
                    int waitMs = checked((int)(_glueSyntheticCharEnumKickMinIntervalMs - elapsedMs));
                    _onGlueSyntheticKickSuppressed?.Invoke(triggerOpcode, waitMs);
                    return true;
                }
            }

            if (!_bridgeState.TryArmPendingGlueKick())
            {
                return true;
            }

            bool forwarded = ForwardSyntheticAcoreCharEnumRequest(output, out bytesWritten);
            if (forwarded)
            {
                _lastGlueSyntheticKickUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            }

            return forwarded;
        }

        private static bool TryParseRetailDbQueryBulk(
            ReadOnlySpan<byte> payload,
            out ParsedDbQueryBulk query,
            out string? error)
        {
            query = default;
            error = null;

            if (payload.Length < 6)
            {
                error = $"DB_QUERY_BULK payload too short: {payload.Length}.";
                return false;
            }

            uint tableHash = BinaryPrimitives.ReadUInt32LittleEndian(payload[..4]);
            ReadOnlySpan<byte> packed = payload[4..];
            int bitOffset = 0;
            if (!TryReadBitsMsbFirst(packed, ref bitOffset, 13, out ulong queryCountRaw))
            {
                error = "Failed to read DB_QUERY_BULK query count.";
                return false;
            }

            if (queryCountRaw > MaxDbQueryBulkRecords)
            {
                error = $"DB_QUERY_BULK query count is out of range: {queryCountRaw}.";
                return false;
            }

            int queryCount = (int)queryCountRaw;
            int byteOffset = (bitOffset + 7) / 8;
            int bytesNeeded = checked(queryCount * sizeof(int));
            if (packed.Length - byteOffset < bytesNeeded)
            {
                error = $"DB_QUERY_BULK payload truncated. QueryCount={queryCount}, Available={packed.Length - byteOffset}, Needed={bytesNeeded}.";
                return false;
            }

            int[] recordIds = GC.AllocateUninitializedArray<int>(queryCount);
            for (int i = 0; i < queryCount; i++)
            {
                int offset = byteOffset + (i * sizeof(int));
                recordIds[i] = BinaryPrimitives.ReadInt32LittleEndian(packed.Slice(offset, sizeof(int)));
            }

            query = new ParsedDbQueryBulk(tableHash, recordIds);
            return true;
        }

        private static bool TryReadBitsMsbFirst(ReadOnlySpan<byte> payload, ref int bitOffset, int bitCount, out ulong value)
        {
            value = 0;
            if (bitCount < 0 || bitCount > 64)
            {
                return false;
            }

            for (int i = 0; i < bitCount; i++)
            {
                int absoluteBit = bitOffset + i;
                int byteIndex = absoluteBit / 8;
                if (byteIndex >= payload.Length)
                {
                    return false;
                }

                int bitIndexInByte = 7 - (absoluteBit % 8);
                int bit = (payload[byteIndex] >> bitIndexInByte) & 1;
                value = (value << 1) | (uint)bit;
            }

            bitOffset += bitCount;
            return true;
        }

        private static bool TryParseRetailBattlenetRequest(
            ReadOnlySpan<byte> payload,
            out ParsedBattlenetRequest request,
            out string? error)
        {
            request = default;
            error = null;

            if (payload.Length < 24)
            {
                error = $"CMSG_BATTLENET_REQUEST payload too short: {payload.Length}.";
                return false;
            }

            ulong methodType = BinaryPrimitives.ReadUInt64LittleEndian(payload[..8]);
            ulong objectId = BinaryPrimitives.ReadUInt64LittleEndian(payload.Slice(8, 8));
            uint token = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(16, 4));
            uint protoSize = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(20, 4));
            if (payload.Length < 24 + protoSize)
            {
                error = $"CMSG_BATTLENET_REQUEST payload truncated. ProtoSize={protoSize}, PayloadBytes={payload.Length}.";
                return false;
            }

            request = new ParsedBattlenetRequest(methodType, objectId, token);
            return true;
        }

        private readonly record struct ParsedDbQueryBulk(uint TableHash, int[] RecordIds);
        private readonly record struct ParsedBattlenetRequest(ulong MethodType, ulong ObjectId, uint Token);
    }

    private sealed class AcorePostAuthServerTranslator
    {
        private const int MaxServerPacketSize = 16 * 1024 * 1024;
        private const int MaxBufferedFramesBeforeAuth = 32;
        private const int MaxBufferedBytesBeforeAuth = 256 * 1024;

        private readonly AuthCrypt _authCrypt;
        private readonly WorldProxyBridgeState _bridgeState;
        private readonly bool _strictStageEnforcement;
        private readonly bool _waitForEnterEncryptedAckGate;
        private readonly bool _probeBareAuthResponseOnly;
        private readonly bool _probeAuthResponseResultOnly;
        private readonly uint _probeAuthResponseResultOnlyCode;
        private readonly bool _probeAuthResponseMinimalSuccessNoAccountData;
        private readonly bool _probeAuthResponseTwwAccountDataProfile;
        private readonly bool _probeAuthResponseTwwAddResultPrefix;
        private readonly bool _probeAuthResponseForceWaitInfoPresent;
        private readonly bool _probeAuthResponseForceCurrentBuildPresent;
        private readonly int _probeAuthResponseAvailableClassesCardinality;
        private readonly int _probeAuthResponseTwwClassMatrixRows;
        private readonly bool _probeAuthResponseTwwUseAcoreExpansionLevels;
        private readonly bool _probeInsertRetailSequencePreludeBeforeAuthResponse;
        private readonly bool _probeInsertRetailSequencePreludeAfterAuthResponse;
        private readonly bool _probeReorderFirstDeferredFrameAfterPrelude;
        private readonly bool _probeFeatureSystemStatusGlueScreenTrinitySemantics;
        private readonly bool _probeCompressAuthResponseAsSmsgCompressedPacket;
        private readonly bool _probeCompressedAuthResponseForceEnvelope;
        private readonly bool _probeCompressedAuthResponseUseRawDeflate;
        private readonly bool _probeCompressedAuthResponseUseStatefulDeflateSyncFlush;
        private readonly int _probeCompressedAuthResponseRawDeflateLevel;
        private readonly bool _probeCompressedAuthResponseChecksumPayloadOnly;
        private readonly uint _probeCompressedAuthResponseChecksumSeed;
        private readonly bool _probeCompressedAuthResponseCompressedChecksumIncludeMetadata;
        private readonly byte[] _probeRetailSequencePreludePayload;
        private readonly AuthResponseFuzzMutation _authResponseFuzzMutation;
        private readonly uint _probeAuthResponseOpcode;
        private readonly byte[] _probeAuthResponseReplayPayload;
        private readonly byte[] _probeAuthResponseReplayCompressedPayload;
        private readonly bool _probeAuthResponseReplayPatchTimeToNow;
        private readonly bool _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount;
        private readonly bool _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount;
        private readonly bool _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset;
        private readonly bool _probeAuthResponseReplayPatchCurrentBuildPresent;
        private readonly bool _probeAuthResponseReplayPatchWaitInfoPresent;
        private readonly bool _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm;
        private readonly bool _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm;
        private readonly bool _probeAuthResponseReplayBisectionResultOnlyErrorOk;
        private readonly byte[] _probeSetTimeZoneInformationPayload;
        private readonly byte[] _probeFeatureSystemStatusGlueScreenPayload;
        private readonly byte[] _probeMirrorVarsPayload;
        private readonly byte[] _probeCacheVersionPayload;
        private readonly byte[] _probeAvailableHotfixesPayload;
        private readonly byte[] _probeAccountDataTimesPayload;
        private readonly byte[] _probeTutorialFlagsPayload;
        private readonly byte[] _probeBattleNetConnectionStatusPayload;
        private readonly uint _acoreRealmId;
        private readonly bool _controlledUnlockEmptyCharEnumEnabled;
        private readonly bool _effectiveSuppressPostAuthBootstrapForProbe;
        private readonly bool _forwardAcoreWardenAsRetailWarden3Data;
        private readonly bool _forwardAcoreAddonInfoAsRetailAddonListRequest;
        private readonly bool _forwardAcoreTutorialFlagsAsRetailTutorialFlags;
        private readonly Func<byte[]?>? _getEnterEncryptedModeFrame;
        private readonly Action<byte[], string>? _onDeferredBootstrapPrepared;
        private readonly Action? _onEnterEncryptedModeSent;
        private readonly Action<string>? _onEnterEncryptedAwaitStart;
        private readonly Action<int, string>? _onBootstrapFlushedWithoutAck;
        private readonly Action<int, string>? _onBootstrapSuppressedForProbe;
        private readonly Action? _onCharEnumReceived;
        private readonly Action<int, int>? _onControlledUnlockApplied;
        private readonly Action<ushort, int>? _onFrameDecoded;
        private readonly Action<ushort, int>? _onDroppedOpcode;
        private readonly HashSet<ushort> _loggedDroppedOpcodes = new();
        private readonly StatefulRawDeflateSyncFlushCompressor? _statefulCompressedAuthResponseCompressor;
        private readonly byte[] _header = new byte[5];
        private readonly List<BufferedServerFrame> _bufferedBeforeAuth = new();
        private bool _authResponseForwarded;
        private int _bufferedBeforeAuthBytes;

        private int _headerBytesRead;
        private int _headerBytesExpected;
        private ushort _currentOpcode;
        private int _payloadBytesExpected;
        private int _payloadBytesRead;
        private byte[] _payloadBuffer = Array.Empty<byte>();

        public AcorePostAuthServerTranslator(
            AuthCrypt authCrypt,
            WorldProxyBridgeState bridgeState,
            bool strictStageEnforcement = true,
            bool waitForEnterEncryptedAckGate = false,
            bool suppressPostAuthBootstrapForProbe = false,
            bool probeBareAuthResponseOnly = false,
            bool probeAuthResponseResultOnly = false,
            uint probeAuthResponseResultOnlyCode = 0,
            bool probeAuthResponseMinimalSuccessNoAccountData = false,
            bool probeAuthResponseTwwAccountDataProfile = false,
            bool probeAuthResponseTwwAddResultPrefix = false,
            bool probeAuthResponseForceWaitInfoPresent = false,
            bool probeAuthResponseForceCurrentBuildPresent = false,
            int probeAuthResponseAvailableClassesCardinality = 1,
            int probeAuthResponseTwwClassMatrixRows = 0,
            bool probeAuthResponseTwwUseAcoreExpansionLevels = false,
            bool probeInsertRetailSequencePreludeBeforeAuthResponse = false,
            bool probeInsertRetailSequencePreludeAfterAuthResponse = false,
            bool probeReorderFirstDeferredFrameAfterPrelude = false,
            bool probeFeatureSystemStatusGlueScreenTrinitySemantics = false,
            bool probeCompressAuthResponseAsSmsgCompressedPacket = false,
            bool probeCompressedAuthResponseForceEnvelope = false,
            bool probeCompressedAuthResponseUseRawDeflate = false,
            bool probeCompressedAuthResponseUseStatefulDeflateSyncFlush = false,
            int probeCompressedAuthResponseRawDeflateLevel = -1,
            bool probeCompressedAuthResponseChecksumPayloadOnly = false,
            long probeCompressedAuthResponseChecksumSeed = TrinityCompressionAdlerSeed,
            bool probeCompressedAuthResponseCompressedChecksumIncludeMetadata = false,
            byte[]? probeRetailSequencePreludePayload = null,
            AuthResponseFuzzMutation authResponseFuzzMutation = default,
            uint probeAuthResponseOpcode = RetailOpcodeSmsgAuthResponse,
            byte[]? probeAuthResponseReplayPayload = null,
            byte[]? probeAuthResponseReplayCompressedPayload = null,
            bool probeAuthResponseReplayPatchTimeToNow = false,
            bool probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount = false,
            bool probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount = false,
            bool probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset = false,
            bool probeAuthResponseReplayPatchCurrentBuildPresent = false,
            bool probeAuthResponseReplayPatchWaitInfoPresent = false,
            bool probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm = false,
            bool probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm = false,
            bool probeAuthResponseReplayBisectionResultOnlyErrorOk = false,
            byte[]? probeSetTimeZoneInformationPayload = null,
            byte[]? probeFeatureSystemStatusGlueScreenPayload = null,
            byte[]? probeMirrorVarsPayload = null,
            byte[]? probeCacheVersionPayload = null,
            byte[]? probeAvailableHotfixesPayload = null,
            byte[]? probeAccountDataTimesPayload = null,
            byte[]? probeTutorialFlagsPayload = null,
            byte[]? probeBattleNetConnectionStatusPayload = null,
            uint acoreRealmId = 1,
            bool controlledUnlockEmptyCharEnumEnabled = false,
            bool forwardAcoreWardenAsRetailWarden3Data = false,
            bool forwardAcoreAddonInfoAsRetailAddonListRequest = false,
            bool forwardAcoreTutorialFlagsAsRetailTutorialFlags = false,
            Func<byte[]?>? getEnterEncryptedModeFrame = null,
            Action<byte[], string>? onDeferredBootstrapPrepared = null,
            Action? onEnterEncryptedModeSent = null,
            Action<string>? onEnterEncryptedAwaitStart = null,
            Action<int, string>? onBootstrapFlushedWithoutAck = null,
            Action<int, string>? onBootstrapSuppressedForProbe = null,
            Action? onCharEnumReceived = null,
            Action<int, int>? onControlledUnlockApplied = null,
            Action<ushort, int>? onFrameDecoded = null,
            Action<ushort, int>? onDroppedOpcode = null)
        {
            _authCrypt = authCrypt ?? throw new ArgumentNullException(nameof(authCrypt));
            _bridgeState = bridgeState ?? throw new ArgumentNullException(nameof(bridgeState));
            _strictStageEnforcement = strictStageEnforcement;
            _waitForEnterEncryptedAckGate = waitForEnterEncryptedAckGate;
            _probeBareAuthResponseOnly = probeBareAuthResponseOnly;
            _probeAuthResponseResultOnly = probeAuthResponseResultOnly;
            _probeAuthResponseResultOnlyCode = probeAuthResponseResultOnlyCode;
            _probeAuthResponseMinimalSuccessNoAccountData = probeAuthResponseMinimalSuccessNoAccountData;
            _probeAuthResponseTwwAccountDataProfile = probeAuthResponseTwwAccountDataProfile;
            _probeAuthResponseTwwAddResultPrefix = probeAuthResponseTwwAddResultPrefix;
            _probeAuthResponseForceWaitInfoPresent = probeAuthResponseForceWaitInfoPresent;
            _probeAuthResponseForceCurrentBuildPresent = probeAuthResponseForceCurrentBuildPresent;
            _probeAuthResponseAvailableClassesCardinality = Math.Clamp(probeAuthResponseAvailableClassesCardinality, 1, 13);
            _probeAuthResponseTwwClassMatrixRows = Math.Clamp(probeAuthResponseTwwClassMatrixRows, 0, AuthResponseClassMatrixHelpers.LegacyRowCount);
            _probeAuthResponseTwwUseAcoreExpansionLevels = probeAuthResponseTwwUseAcoreExpansionLevels;
            _probeInsertRetailSequencePreludeBeforeAuthResponse = probeInsertRetailSequencePreludeBeforeAuthResponse;
            _probeInsertRetailSequencePreludeAfterAuthResponse =
                probeInsertRetailSequencePreludeAfterAuthResponse &&
                !probeInsertRetailSequencePreludeBeforeAuthResponse;
            _probeReorderFirstDeferredFrameAfterPrelude =
                probeReorderFirstDeferredFrameAfterPrelude &&
                _probeInsertRetailSequencePreludeAfterAuthResponse;
            _probeFeatureSystemStatusGlueScreenTrinitySemantics = probeFeatureSystemStatusGlueScreenTrinitySemantics;
            _probeCompressAuthResponseAsSmsgCompressedPacket = probeCompressAuthResponseAsSmsgCompressedPacket;
            _probeCompressedAuthResponseForceEnvelope = probeCompressedAuthResponseForceEnvelope;
            _probeCompressedAuthResponseUseRawDeflate = probeCompressedAuthResponseUseRawDeflate;
            _probeCompressedAuthResponseUseStatefulDeflateSyncFlush = probeCompressedAuthResponseUseStatefulDeflateSyncFlush;
            _probeCompressedAuthResponseRawDeflateLevel = RetailCompressionCodec.NormalizeDeflateLevel(probeCompressedAuthResponseRawDeflateLevel);
            _probeCompressedAuthResponseChecksumPayloadOnly = probeCompressedAuthResponseChecksumPayloadOnly;
            _probeCompressedAuthResponseChecksumSeed = RetailCompressionCodec.NormalizeChecksumSeed(probeCompressedAuthResponseChecksumSeed, TrinityCompressionAdlerSeed);
            _probeCompressedAuthResponseCompressedChecksumIncludeMetadata = probeCompressedAuthResponseCompressedChecksumIncludeMetadata;
            _probeRetailSequencePreludePayload = probeRetailSequencePreludePayload is { Length: 4 }
                ? probeRetailSequencePreludePayload.ToArray()
                : [0, 0, 0, 0];
            _authResponseFuzzMutation = authResponseFuzzMutation;
            _probeAuthResponseOpcode = probeAuthResponseOpcode == 0 ? RetailOpcodeSmsgAuthResponse : probeAuthResponseOpcode;
            _probeAuthResponseReplayPayload = probeAuthResponseReplayPayload is { Length: > 0 }
                ? probeAuthResponseReplayPayload.ToArray()
                : Array.Empty<byte>();
            _probeAuthResponseReplayCompressedPayload = probeAuthResponseReplayCompressedPayload is { Length: > 0 }
                ? probeAuthResponseReplayCompressedPayload.ToArray()
                : Array.Empty<byte>();
            _probeAuthResponseReplayPatchTimeToNow = probeAuthResponseReplayPatchTimeToNow;
            _probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount = probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount;
            _probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount = probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount;
            _probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset = probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset;
            _probeAuthResponseReplayPatchCurrentBuildPresent = probeAuthResponseReplayPatchCurrentBuildPresent;
            _probeAuthResponseReplayPatchWaitInfoPresent = probeAuthResponseReplayPatchWaitInfoPresent;
            _probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm = probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm;
            _probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm = probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm;
            _probeAuthResponseReplayBisectionResultOnlyErrorOk = probeAuthResponseReplayBisectionResultOnlyErrorOk;
            _probeSetTimeZoneInformationPayload = probeSetTimeZoneInformationPayload is { Length: > 0 }
                ? probeSetTimeZoneInformationPayload.ToArray()
                : Array.Empty<byte>();
            _probeFeatureSystemStatusGlueScreenPayload = probeFeatureSystemStatusGlueScreenPayload is { Length: > 0 }
                ? probeFeatureSystemStatusGlueScreenPayload.ToArray()
                : Array.Empty<byte>();
            _probeMirrorVarsPayload = probeMirrorVarsPayload is { Length: > 0 }
                ? probeMirrorVarsPayload.ToArray()
                : Array.Empty<byte>();
            _probeCacheVersionPayload = probeCacheVersionPayload is { Length: > 0 }
                ? probeCacheVersionPayload.ToArray()
                : Array.Empty<byte>();
            _probeAvailableHotfixesPayload = probeAvailableHotfixesPayload is { Length: > 0 }
                ? probeAvailableHotfixesPayload.ToArray()
                : Array.Empty<byte>();
            _probeAccountDataTimesPayload = probeAccountDataTimesPayload is { Length: > 0 }
                ? probeAccountDataTimesPayload.ToArray()
                : Array.Empty<byte>();
            _probeTutorialFlagsPayload = probeTutorialFlagsPayload is { Length: > 0 }
                ? probeTutorialFlagsPayload.ToArray()
                : Array.Empty<byte>();
            _probeBattleNetConnectionStatusPayload = probeBattleNetConnectionStatusPayload is { Length: > 0 }
                ? probeBattleNetConnectionStatusPayload.ToArray()
                : Array.Empty<byte>();
            _acoreRealmId = acoreRealmId == 0 ? 1u : acoreRealmId;
            _controlledUnlockEmptyCharEnumEnabled = controlledUnlockEmptyCharEnumEnabled;
            _effectiveSuppressPostAuthBootstrapForProbe =
                suppressPostAuthBootstrapForProbe && !probeBareAuthResponseOnly;
            _forwardAcoreWardenAsRetailWarden3Data = forwardAcoreWardenAsRetailWarden3Data;
            _forwardAcoreAddonInfoAsRetailAddonListRequest = forwardAcoreAddonInfoAsRetailAddonListRequest;
            _forwardAcoreTutorialFlagsAsRetailTutorialFlags = forwardAcoreTutorialFlagsAsRetailTutorialFlags;
            _getEnterEncryptedModeFrame = getEnterEncryptedModeFrame;
            _onDeferredBootstrapPrepared = onDeferredBootstrapPrepared;
            _onEnterEncryptedModeSent = onEnterEncryptedModeSent;
            _onEnterEncryptedAwaitStart = onEnterEncryptedAwaitStart;
            _onBootstrapFlushedWithoutAck = onBootstrapFlushedWithoutAck;
            _onBootstrapSuppressedForProbe = onBootstrapSuppressedForProbe;
            _onCharEnumReceived = onCharEnumReceived;
            _onControlledUnlockApplied = onControlledUnlockApplied;
            _onFrameDecoded = onFrameDecoded;
            _onDroppedOpcode = onDroppedOpcode;
            _statefulCompressedAuthResponseCompressor =
                _probeCompressAuthResponseAsSmsgCompressedPacket &&
                _probeCompressedAuthResponseUseRawDeflate &&
                _probeCompressedAuthResponseUseStatefulDeflateSyncFlush
                    ? new StatefulRawDeflateSyncFlushCompressor(_probeCompressedAuthResponseRawDeflateLevel)
                    : null;
        }

        public bool TryTransform(ReadOnlySequence<byte> input, IBufferWriter<byte> output, out long bytesWritten, out string? error)
        {
            bytesWritten = 0;
            error = null;

            foreach (ReadOnlyMemory<byte> segment in input)
            {
                ReadOnlySpan<byte> span = segment.Span;
                for (int idx = 0; idx < span.Length; idx++)
                {
                    byte current = span[idx];

                    if (_payloadBytesExpected > 0)
                    {
                        _payloadBuffer[_payloadBytesRead++] = current;

                        if (_payloadBytesRead < _payloadBytesExpected)
                        {
                            continue;
                        }

                        if (!TryTranslateDecodedFrame(
                                _currentOpcode,
                                _payloadBuffer.AsSpan(0, _payloadBytesExpected),
                                output,
                                out long frameBytes,
                                out error))
                        {
                            return false;
                        }

                        bytesWritten += frameBytes;
                        ResetFrameState();
                        continue;
                    }

                    _header[_headerBytesRead] = current;
                    _authCrypt.TransformServerToClient(_header.AsSpan(_headerBytesRead, 1));
                    _headerBytesRead++;

                    if (_headerBytesRead == 1)
                    {
                        _headerBytesExpected = (_header[0] & 0x80) != 0 ? 5 : 4;
                    }

                    if (_headerBytesRead < _headerBytesExpected)
                    {
                        continue;
                    }

                    if (!TryDecodeServerPacketSize(_header.AsSpan(0, _headerBytesExpected), out int packetSizeIncludingOpcode, out string decodeError))
                    {
                        error = decodeError;
                        return false;
                    }

                    int payloadBytes = packetSizeIncludingOpcode - 2;
                    if (payloadBytes < 0 || payloadBytes > MaxServerPacketSize)
                    {
                        error = $"Invalid AC server payload size in header: {payloadBytes}.";
                        return false;
                    }

                    _currentOpcode = _headerBytesExpected == 4
                        ? BinaryPrimitives.ReadUInt16LittleEndian(_header.AsSpan(2, 2))
                        : BinaryPrimitives.ReadUInt16LittleEndian(_header.AsSpan(3, 2));
                    _payloadBytesExpected = payloadBytes;
                    _payloadBytesRead = 0;
                    _onFrameDecoded?.Invoke(_currentOpcode, _payloadBytesExpected);

                    if (_payloadBytesExpected == 0)
                    {
                        if (!TryTranslateDecodedFrame(_currentOpcode, ReadOnlySpan<byte>.Empty, output, out long frameBytes, out error))
                        {
                            return false;
                        }

                        bytesWritten += frameBytes;
                        ResetFrameState();
                        continue;
                    }

                    if (_payloadBuffer.Length < _payloadBytesExpected)
                    {
                        _payloadBuffer = GC.AllocateUninitializedArray<byte>(_payloadBytesExpected);
                    }
                }
            }

            return true;
        }

        private bool TryTranslateDecodedFrame(ushort opcode, ReadOnlySpan<byte> payload, IBufferWriter<byte> output, out long bytesWritten, out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (!_bridgeState.ValidateServerOpcode(opcode, _strictStageEnforcement, out string? stageError))
            {
                error = stageError;
                return false;
            }

            // Retail client expects auth response first. Buffer AC side packets that arrive before it,
            // then flush them in order right after auth response has been forwarded.
            if (!_authResponseForwarded)
            {
                if (opcode != AcoreOpcodeSmsgAuthResponse)
                {
                    if (_bufferedBeforeAuth.Count >= MaxBufferedFramesBeforeAuth ||
                        _bufferedBeforeAuthBytes + payload.Length > MaxBufferedBytesBeforeAuth)
                    {
                        if (_loggedDroppedOpcodes.Add(opcode))
                        {
                            _onDroppedOpcode?.Invoke(opcode, payload.Length);
                        }

                        return true;
                    }

                    byte[] payloadCopy = GC.AllocateUninitializedArray<byte>(payload.Length);
                    payload.CopyTo(payloadCopy);
                    _bufferedBeforeAuth.Add(new BufferedServerFrame(opcode, payloadCopy));
                    _bufferedBeforeAuthBytes += payload.Length;
                    return true;
                }

                byte[] mapped;
                bool authResponseAlreadyCompressed = false;
                if (_probeAuthResponseReplayPayload.Length > 0)
                {
                    if (_probeAuthResponseReplayBisectionResultOnlyErrorOk)
                    {
                        Span<byte> resultOnlyPayload = stackalloc byte[sizeof(uint)];
                        BinaryPrimitives.WriteUInt32LittleEndian(resultOnlyPayload, 0u); // ERROR_OK
                        mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(_probeAuthResponseOpcode, resultOnlyPayload);
                    }
                    else
                    {
                    ReadOnlySpan<byte> replayPayload = _probeAuthResponseReplayPayload;
                    byte[]? patchedReplayPayload = null;
                    if (_probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount)
                    {
                        if (!TryPatchAuthResponseReplayPayloadExpansionLevelsFromAcoreAccount(
                                replayPayload,
                                payload,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload expansion levels.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount)
                    {
                        if (!TryPatchAuthResponseReplayPayloadClassMatrixExpansionTripletsFromAcoreAccount(
                                replayPayload,
                                payload,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload class-matrix expansion triplets.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset)
                    {
                        if (!TryPatchAuthResponseReplayPayloadClassMatrixCardinalityToRuntimeSubset(
                                replayPayload,
                                payload,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload class-matrix cardinality to runtime subset.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchCurrentBuildPresent)
                    {
                        if (!TryPatchAuthResponseReplayPayloadCurrentBuildPresent(
                                replayPayload,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload CurrentBuild optional block.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchWaitInfoPresent)
                    {
                        if (!TryPatchAuthResponseReplayPayloadWaitInfoPresent(
                                replayPayload,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload WaitInfo optional block.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm)
                    {
                        if (!TryPatchAuthResponseReplayPayloadVirtualRealmEntryFromRuntimeRealm(
                                replayPayload,
                                _acoreRealmId,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload virtual realm entry.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm)
                    {
                        if (!TryPatchAuthResponseReplayPayloadTopVirtualRealmAddressFromRuntimeRealm(
                                replayPayload,
                                _acoreRealmId,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload top virtual realm address.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    if (_probeAuthResponseReplayPatchTimeToNow)
                    {
                        if (!TryPatchAuthResponseReplayPayloadTimeUnixNow(
                                replayPayload,
                                out patchedReplayPayload,
                                out string? patchError))
                        {
                            error = patchError ?? "Failed to patch AUTH_RESPONSE replay payload time field.";
                            return false;
                        }

                        replayPayload = patchedReplayPayload;
                    }

                    mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(_probeAuthResponseOpcode, replayPayload);

                    if (_probeAuthResponseReplayCompressedPayload.Length > 0)
                    {
                        mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(
                            RetailOpcodeSmsgCompressedPacket,
                            _probeAuthResponseReplayCompressedPayload);
                        authResponseAlreadyCompressed = true;
                    }
                    }
                }
                else if (!TryBuildRetailAuthResponseFromAcore(
                             payload,
                             _probeAuthResponseResultOnly,
                             _probeAuthResponseResultOnlyCode,
                             _probeAuthResponseMinimalSuccessNoAccountData,
                             _probeAuthResponseTwwAccountDataProfile,
                             _probeAuthResponseTwwAddResultPrefix,
                             _probeAuthResponseForceWaitInfoPresent,
                             _probeAuthResponseForceCurrentBuildPresent,
                             _probeAuthResponseAvailableClassesCardinality,
                             _probeAuthResponseTwwClassMatrixRows,
                             _probeAuthResponseTwwUseAcoreExpansionLevels,
                             _authResponseFuzzMutation,
                             _probeAuthResponseOpcode,
                             _acoreRealmId,
                             out mapped,
                             out error))
                {
                    return false;
                }

                if (_probeCompressAuthResponseAsSmsgCompressedPacket && !authResponseAlreadyCompressed)
                {
                    if (!RetailCompressedPacketWrapper.TryBuildRetailCompressedPacketFrame(
                            mapped,
                            _probeCompressedAuthResponseForceEnvelope,
                            _probeCompressedAuthResponseUseRawDeflate,
                            _probeCompressedAuthResponseUseStatefulDeflateSyncFlush,
                            _probeCompressedAuthResponseRawDeflateLevel,
                            _probeCompressedAuthResponseChecksumPayloadOnly,
                            _probeCompressedAuthResponseChecksumSeed,
                            _probeCompressedAuthResponseCompressedChecksumIncludeMetadata,
                            _statefulCompressedAuthResponseCompressor,
                            RetailOpcodeSmsgCompressedPacket,
                            TrinityCompressionThresholdBytes,
                            out byte[] compressedAuthResponse,
                            out string? compressionError))
                    {
                        error = $"Failed to wrap AUTH_RESPONSE as SMSG_COMPRESSED_PACKET: {compressionError ?? "<unknown>"}";
                        return false;
                    }

                    mapped = compressedAuthResponse;
                }

                var bootstrapBuffer = new ArrayBufferWriter<byte>(1024);
                var stagedOpcodes = new List<string>(16);

                if (_probeInsertRetailSequencePreludeBeforeAuthResponse)
                {
                    byte[] prelude = BuildRetailAuthSequencePreludeFrame(_probeRetailSequencePreludePayload);
                    bootstrapBuffer.Write(prelude);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAuthSequencePrelude:X8}");
                }

                bootstrapBuffer.Write(mapped);
                uint stagedAuthOpcode = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(16, 4));
                stagedOpcodes.Add($"0x{stagedAuthOpcode:X8}");

                if (_probeInsertRetailSequencePreludeAfterAuthResponse)
                {
                    byte[] prelude = BuildRetailAuthSequencePreludeFrame(_probeRetailSequencePreludePayload);
                    bootstrapBuffer.Write(prelude);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAuthSequencePrelude:X8}");
                }

                if (!_probeBareAuthResponseOnly)
                {
                    // Trinity-authenticated bootstrap parity:
                    // AUTH_RESPONSE -> TIME_ZONE -> FEATURE -> MIRROR_VARS ->
                    // CACHE_VERSION -> AVAILABLE_HOTFIXES -> ACCOUNT_DATA_TIMES ->
                    // TUTORIAL_FLAGS -> BATTLE_NET_CONNECTION_STATUS.
                    byte[]? cacheVersionPayload = null;
                    byte[]? tutorialFlagsPayload = null;

                    for (int i = 0; i < _bufferedBeforeAuth.Count; i++)
                    {
                        BufferedServerFrame buffered = _bufferedBeforeAuth[i];
                        switch (buffered.Opcode)
                        {
                            case AcoreOpcodeSmsgClientCacheVersion when cacheVersionPayload is null:
                                cacheVersionPayload = buffered.Payload;
                                break;
                            case AcoreOpcodeSmsgTutorialFlags
                                when _forwardAcoreTutorialFlagsAsRetailTutorialFlags &&
                                     tutorialFlagsPayload is null &&
                                     buffered.Payload.Length == RetailTutorialValuesCount * sizeof(uint):
                                tutorialFlagsPayload = buffered.Payload;
                                break;
                            default:
                                if (_loggedDroppedOpcodes.Add(buffered.Opcode))
                                {
                                    _onDroppedOpcode?.Invoke(buffered.Opcode, buffered.Payload.Length);
                                }

                                break;
                        }
                    }

                    byte[] timezone = _probeSetTimeZoneInformationPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgSetTimeZoneInformation, _probeSetTimeZoneInformationPayload)
                        : BuildRetailSetTimeZoneInformationFrame();
                    bootstrapBuffer.Write(timezone);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgSetTimeZoneInformation:X8}");

                    byte[] features = _probeFeatureSystemStatusGlueScreenPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgFeatureSystemStatusGlueScreen, _probeFeatureSystemStatusGlueScreenPayload)
                        : BuildRetailFeatureSystemStatusGlueScreenFrame(_probeFeatureSystemStatusGlueScreenTrinitySemantics);
                    bootstrapBuffer.Write(features);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgFeatureSystemStatusGlueScreen:X8}");

                    byte[] mirrorVars = _probeMirrorVarsPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgMirrorVars, _probeMirrorVarsPayload)
                        : BuildRetailMirrorVarsFrame();
                    bootstrapBuffer.Write(mirrorVars);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgMirrorVars:X8}");

                    byte[] cacheVersion = _probeCacheVersionPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgCacheVersion, _probeCacheVersionPayload)
                        : BuildRetailCacheVersionFrame(cacheVersionPayload);
                    bootstrapBuffer.Write(cacheVersion);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgCacheVersion:X8}");

                    byte[] availableHotfixes = _probeAvailableHotfixesPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAvailableHotfixes, _probeAvailableHotfixesPayload)
                        : BuildRetailAvailableHotfixesFrame(_acoreRealmId);
                    bootstrapBuffer.Write(availableHotfixes);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAvailableHotfixes:X8}");

                    byte[] accountDataTimes = _probeAccountDataTimesPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAccountDataTimes, _probeAccountDataTimesPayload)
                        : BuildRetailAccountDataTimesFrame();
                    bootstrapBuffer.Write(accountDataTimes);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgAccountDataTimes:X8}");

                    byte[] tutorialFlags = _probeTutorialFlagsPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTutorialFlags, _probeTutorialFlagsPayload)
                        : BuildRetailTutorialFlagsFrame(tutorialFlagsPayload);
                    bootstrapBuffer.Write(tutorialFlags);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgTutorialFlags:X8}");

                    byte[] battleNetConnectionStatus = _probeBattleNetConnectionStatusPayload.Length > 0
                        ? RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgBattleNetConnectionStatus, _probeBattleNetConnectionStatusPayload)
                        : BuildRetailBattleNetConnectionStatusFrame(state: 1, suppressNotification: true);
                    bootstrapBuffer.Write(battleNetConnectionStatus);
                    stagedOpcodes.Add($"0x{RetailOpcodeSmsgBattleNetConnectionStatus:X8}");
                }
                else
                {
                    for (int i = 0; i < _bufferedBeforeAuth.Count; i++)
                    {
                        BufferedServerFrame buffered = _bufferedBeforeAuth[i];
                        if (_loggedDroppedOpcodes.Add(buffered.Opcode))
                        {
                            _onDroppedOpcode?.Invoke(buffered.Opcode, buffered.Payload.Length);
                        }
                    }
                }

                if (_probeReorderFirstDeferredFrameAfterPrelude)
                {
                    ReorderFirstDeferredFrameAfterPrelude(bootstrapBuffer, stagedOpcodes);
                }

                byte[] bootstrapPayload = bootstrapBuffer.WrittenMemory.ToArray();
                string stagedOpcodeList = stagedOpcodes.Count > 0
                    ? string.Join(", ", stagedOpcodes)
                    : "<none>";

                byte[]? enterEncryptedModeFrame = _getEnterEncryptedModeFrame?.Invoke();
                if (enterEncryptedModeFrame is { Length: > 0 })
                {
                    if (!TryWriteRetailServerFrame(enterEncryptedModeFrame, output, out long enterEncryptedBytes, out error))
                    {
                        return false;
                    }

                    bytesWritten += enterEncryptedBytes;
                    _onEnterEncryptedModeSent?.Invoke();

                    if (_waitForEnterEncryptedAckGate)
                    {
                        _onDeferredBootstrapPrepared?.Invoke(bootstrapPayload, stagedOpcodeList);
                        _onEnterEncryptedAwaitStart?.Invoke(stagedOpcodeList);
                    }
                    else
                    {
                        if (_effectiveSuppressPostAuthBootstrapForProbe)
                        {
                            _onBootstrapSuppressedForProbe?.Invoke(bootstrapPayload.Length, stagedOpcodeList);
                        }
                        else
                        {
                            // Trinity-like behavior: do not block post-auth bootstrap on plaintext ACK.
                            if (!TryWriteRetailServerFrameBatch(bootstrapPayload, output, out long bootstrapBytes, out error))
                            {
                                return false;
                            }

                            bytesWritten += bootstrapBytes;
                            _onBootstrapFlushedWithoutAck?.Invoke(bootstrapPayload.Length, stagedOpcodeList);
                        }
                    }
                }
                else
                {
                    if (_effectiveSuppressPostAuthBootstrapForProbe)
                    {
                        _onBootstrapSuppressedForProbe?.Invoke(bootstrapPayload.Length, stagedOpcodeList);
                    }
                    else
                    {
                        if (!TryWriteRetailServerFrameBatch(bootstrapPayload, output, out long bootstrapBytes, out error))
                        {
                            return false;
                        }

                        bytesWritten += bootstrapBytes;
                    }
                }

                _authResponseForwarded = true;
                _bufferedBeforeAuth.Clear();
                _bufferedBeforeAuthBytes = 0;
                return true;
            }

            return TryTranslateAfterAuth(opcode, payload, output, out bytesWritten, out error);
        }

        private static void ReorderFirstDeferredFrameAfterPrelude(ArrayBufferWriter<byte> bootstrapBuffer, List<string> stagedOpcodes)
        {
            if (bootstrapBuffer.WrittenCount <= 0)
            {
                return;
            }

            byte[] snapshot = bootstrapBuffer.WrittenMemory.ToArray();
            if (!RetailFrameCodec.TrySplitRetailWorldFrames(snapshot, out List<RetailFrameChunk> frames, out _))
            {
                return;
            }

            if (frames.Count < 2)
            {
                return;
            }

            int preludeFrameIndex = frames.FindIndex(frame => frame.Opcode == RetailOpcodeSmsgAuthSequencePrelude);
            if (preludeFrameIndex <= 0)
            {
                return;
            }

            RetailFrameChunk firstFrame = frames[0];
            frames.RemoveAt(0);
            int insertIndex = Math.Min(preludeFrameIndex, frames.Count);
            frames.Insert(insertIndex, firstFrame);

            bootstrapBuffer.Clear();
            for (int i = 0; i < frames.Count; i++)
            {
                bootstrapBuffer.Write(frames[i].Frame);
            }

            if (stagedOpcodes.Count < 2)
            {
                return;
            }

            string preludeOpcodeToken = $"0x{RetailOpcodeSmsgAuthSequencePrelude:X8}";
            int preludeOpcodeIndex = stagedOpcodes.IndexOf(preludeOpcodeToken);
            if (preludeOpcodeIndex <= 0)
            {
                return;
            }

            string firstStagedOpcode = stagedOpcodes[0];
            stagedOpcodes.RemoveAt(0);
            int stagedInsertIndex = Math.Min(preludeOpcodeIndex, stagedOpcodes.Count);
            stagedOpcodes.Insert(stagedInsertIndex, firstStagedOpcode);
        }

        private bool TryTranslateAfterAuth(ushort opcode, ReadOnlySpan<byte> payload, IBufferWriter<byte> output, out long bytesWritten, out string? error)
        {
            bytesWritten = 0;
            error = null;
            bool ackGatePending = _waitForEnterEncryptedAckGate && !_bridgeState.AckObserved;

            if (_probeBareAuthResponseOnly && opcode != AcoreOpcodeSmsgCharEnum)
            {
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            // During ACK-gated bootstrap, these frames are already staged in deferred payload.
            // Suppress pre-ACK passthrough duplicates to keep pre-ACK sequence aligned with Trinity.
            if (ackGatePending &&
                (opcode == AcoreOpcodeSmsgTutorialFlags || opcode == AcoreOpcodeSmsgClientCacheVersion))
            {
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }
                return true;
            }

            if (opcode == AcoreOpcodeSmsgPong)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgPong, payload);
                return TryWriteRetailServerFrame(mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgCharEnum)
            {
                bool syntheticGlueTurn = _bridgeState.ConsumePendingGlueKick();
                bool isEmptyAcoreCharEnum = payload.Length == 1 && payload[0] == 0;
                bool suppressSyntheticEmptyRefresh =
                    syntheticGlueTurn &&
                    _controlledUnlockEmptyCharEnumEnabled &&
                    isEmptyAcoreCharEnum;

                bytesWritten = 0;
                bool wroteCharEnumToClient = false;
                if (!suppressSyntheticEmptyRefresh)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgEnumCharactersResult, payload);
                    if (_controlledUnlockEmptyCharEnumEnabled &&
                        TryBuildControlledUnlockEmptyCharEnumFrame(payload, out byte[] unlockedMapped))
                    {
                        mapped = unlockedMapped;
                        _onControlledUnlockApplied?.Invoke(payload.Length, Math.Max(0, mapped.Length - 20));
                    }

                    if (!TryWriteRetailServerFrame(mapped, output, out long charEnumBytes, out error))
                    {
                        return false;
                    }

                    bytesWritten += charEnumBytes;
                    wroteCharEnumToClient = true;
                    _onCharEnumReceived?.Invoke();

                    if (!TryWriteRetailServerFrame(
                            BuildRetailAccountItemCollectionDataFrame(),
                            output,
                            out long accountCollectionBytes,
                            out string? accountCollectionError))
                    {
                        error = accountCollectionError ?? "Failed to write synthetic SMSG_ACCOUNT_ITEM_COLLECTION_DATA.";
                        return false;
                    }

                    bytesWritten += accountCollectionBytes;
                }

                if (wroteCharEnumToClient || syntheticGlueTurn)
                {
                    bool shouldSendSocialContractResponse = _bridgeState.ConsumePendingSocialContractRequest();
                    bool shouldSendUndeleteCooldownStatusResponse = _bridgeState.ConsumePendingUndeleteCooldownStatusRequest();
                    bool shouldSendHotfixConnect = _bridgeState.ConsumePendingHotfixRequest();
                    bool shouldSendServerTimeOffset = _bridgeState.ConsumePendingServerTimeOffsetRequest();

                    // Emit pending glue responses in the same turn as enum refresh.
                    if (shouldSendSocialContractResponse)
                    {
                        if (!TryWriteRetailServerFrame(
                                BuildRetailSocialContractRequestResponseFrame(showSocialContract: false),
                                output,
                                out long socialBytes,
                                out string? socialError))
                        {
                            error = socialError ?? "Failed to write synthetic SMSG_SOCIAL_CONTRACT_REQUEST_RESPONSE.";
                            return false;
                        }

                        bytesWritten += socialBytes;
                    }

                    if (shouldSendUndeleteCooldownStatusResponse)
                    {
                        if (!TryWriteRetailServerFrame(
                                BuildRetailUndeleteCooldownStatusResponseFrame(
                                    maxCooldownSeconds: 0u,
                                    currentCooldownSeconds: 0u,
                                    onCooldown: false),
                                output,
                                out long undeleteBytes,
                                out string? undeleteError))
                        {
                            error = undeleteError ?? "Failed to write synthetic SMSG_UNDELETE_COOLDOWN_STATUS_RESPONSE.";
                            return false;
                        }

                        bytesWritten += undeleteBytes;
                    }

                    if (shouldSendHotfixConnect)
                    {
                        if (!TryWriteRetailServerFrame(
                                BuildRetailHotfixConnectFrame(),
                                output,
                                out long hotfixBytes,
                                out string? hotfixError))
                        {
                            error = hotfixError ?? "Failed to write synthetic SMSG_HOTFIX_CONNECT.";
                            return false;
                        }

                        bytesWritten += hotfixBytes;
                    }

                    while (_bridgeState.TryDequeuePendingBattleNetResponse(out ulong methodType, out ulong objectId, out uint token))
                    {
                        if (!TryWriteRetailServerFrame(
                                BuildRetailBattleNetResponseFrame(
                                    methodType: methodType,
                                    objectId: objectId,
                                    token: token,
                                    statusCode: 0u,
                                    data: ReadOnlySpan<byte>.Empty),
                                output,
                                out long battleNetBytes,
                                out string? battleNetError))
                        {
                            error = battleNetError ?? "Failed to write synthetic SMSG_BATTLENET_RESPONSE.";
                            return false;
                        }

                        bytesWritten += battleNetBytes;
                    }

                    if (shouldSendServerTimeOffset)
                    {
                        if (!TryWriteRetailServerFrame(
                                BuildRetailServerTimeOffsetFrame(DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
                                output,
                                out long serverTimeBytes,
                                out string? serverTimeError))
                        {
                            error = serverTimeError ?? "Failed to write synthetic SMSG_SERVER_TIME_OFFSET.";
                            return false;
                        }

                        bytesWritten += serverTimeBytes;
                    }

                    uint dbReplyTimestamp = checked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                    while (_bridgeState.TryDequeuePendingDbQueryBulkReplies(out uint tableHash, out int[] recordIds))
                    {
                        for (int i = 0; i < recordIds.Length; i++)
                        {
                            if (!TryWriteRetailServerFrame(
                                    BuildRetailDbReplyFrame(
                                        tableHash: tableHash,
                                        recordId: recordIds[i],
                                        timestamp: dbReplyTimestamp,
                                        status: 3, // DB2Manager::HotfixRecord::Status::Invalid
                                        data: ReadOnlySpan<byte>.Empty),
                                    output,
                                    out long dbReplyBytes,
                                    out string? dbReplyError))
                            {
                                error = dbReplyError ?? "Failed to write synthetic SMSG_DB_REPLY.";
                                return false;
                            }

                            bytesWritten += dbReplyBytes;
                        }
                    }
                }

                return true;
            }

            if (opcode == AcoreOpcodeSmsgTimeSyncRequest)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTimeSyncRequest, payload);
                return TryWriteRetailServerFrame(mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgWardenData)
            {
                if (_forwardAcoreWardenAsRetailWarden3Data)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgWarden3Data, payload);
                    return TryWriteRetailServerFrame(mapped, output, out bytesWritten, out error);
                }

                // Legacy AC Warden payload is not retail-compatible at this stage.
                // Drop until probe confirms mapping viability.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (opcode == AcoreOpcodeSmsgAddonInfo)
            {
                if (_forwardAcoreAddonInfoAsRetailAddonListRequest)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgAddonListRequest, payload);
                    return TryWriteRetailServerFrame(mapped, output, out bytesWritten, out error);
                }

                // Same as Warden: AC legacy addon blob does not match retail parser expectations.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (opcode == AcoreOpcodeSmsgClientCacheVersion)
            {
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgCacheVersion, payload);
                return TryWriteRetailServerFrame(mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgTutorialFlags)
            {
                if (_forwardAcoreTutorialFlagsAsRetailTutorialFlags)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTutorialFlags, payload);
                    return TryWriteRetailServerFrame(mapped, output, out bytesWritten, out error);
                }

                // Optional data; safe to suppress while auth bootstrap parity is incomplete.
                if (_loggedDroppedOpcodes.Add(opcode))
                {
                    _onDroppedOpcode?.Invoke(opcode, payload.Length);
                }

                return true;
            }

            if (_loggedDroppedOpcodes.Add(opcode))
            {
                _onDroppedOpcode?.Invoke(opcode, payload.Length);
            }

            return true;
        }

        private static bool TryBuildControlledUnlockEmptyCharEnumFrame(
            ReadOnlySpan<byte> acPayload,
            out byte[] retailFrame)
        {
            retailFrame = Array.Empty<byte>();

            // AzerothCore 3.3.5a SMSG_CHAR_ENUM encodes char count in the first byte.
            // We only override the known empty-list case (count=0, payload length=1).
            if (acPayload.Length != 1 || acPayload[0] != 0)
            {
                return false;
            }

            retailFrame = BuildRetailEmptyEnumCharactersResultFrame();
            return true;
        }

        private bool TryWriteRetailServerFrame(
            byte[] plainFrame,
            IBufferWriter<byte> output,
            out long bytesWritten,
            out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (!_bridgeState.TryProtectRetailServerFrame(plainFrame, out byte[] protectedFrame, out _, out string? protectError))
            {
                error = $"Failed to protect Retail server frame: {protectError ?? "<unknown>"}";
                return false;
            }

            output.Write(protectedFrame);
            bytesWritten = protectedFrame.Length;
            return true;
        }

        private bool TryWriteRetailServerFrameBatch(
            ReadOnlySpan<byte> payload,
            IBufferWriter<byte> output,
            out long bytesWritten,
            out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (!RetailFrameCodec.TrySplitRetailWorldFrames(payload, out List<RetailFrameChunk> frames, out string? splitError))
            {
                error = splitError ?? "Failed to split retail frame batch.";
                return false;
            }

            for (int index = 0; index < frames.Count; index++)
            {
                RetailFrameChunk frame = frames[index];
                if (!TryWriteRetailServerFrame(frame.Frame, output, out long frameBytes, out error))
                {
                    return false;
                }

                bytesWritten += frameBytes;
            }

            return true;
        }

        private static bool TryDecodeServerPacketSize(ReadOnlySpan<byte> header, out int packetSizeIncludingOpcode, out string error)
        {
            packetSizeIncludingOpcode = 0;
            error = string.Empty;

            if (header.Length == 4)
            {
                packetSizeIncludingOpcode = ((header[0] & 0x7F) << 8) | header[1];
            }
            else if (header.Length == 5)
            {
                packetSizeIncludingOpcode = ((header[0] & 0x7F) << 16) | (header[1] << 8) | header[2];
            }
            else
            {
                error = $"Unsupported AC server header length: {header.Length}.";
                return false;
            }

            if (packetSizeIncludingOpcode < 2)
            {
                error = $"Invalid AC server packet size field: {packetSizeIncludingOpcode}.";
                return false;
            }

            return true;
        }

        private static byte ResolveAcoreAccountExpansionLevel(ReadOnlySpan<byte> acPayload)
        {
            const byte ExpansionTww = 10;
            const byte ExpansionWotlk = 2;

            byte accountExpansion = acPayload.Length >= 11
                ? (byte)Math.Clamp(acPayload[10], (byte)0, ExpansionTww)
                : ExpansionWotlk;
            if (accountExpansion == 0)
            {
                accountExpansion = ExpansionWotlk;
            }

            return accountExpansion;
        }

        private static bool IsClassAllowedForExpansion(byte classId, byte accountExpansion)
        {
            return classId switch
            {
                1 or 2 or 3 or 4 or 5 or 6 or 7 or 8 or 9 or 11 => true, // Vanilla/WotLK-era classes
                10 => accountExpansion >= 5, // Monk (MoP)
                12 => accountExpansion >= 6, // Demon Hunter (Legion)
                13 => accountExpansion >= 10, // Evoker (Dragonflight+)
                _ => false
            };
        }

        private static uint BuildRuntimeVirtualRealmAddress(uint acoreRealmId)
        {
            uint realmId = acoreRealmId != 0 ? acoreRealmId : 1u;
            return (1u << 24) | (1u << 16) | (realmId & 0xFFFFu);
        }

        private static bool TryPatchAuthResponseReplayPayloadTopVirtualRealmAddressFromRuntimeRealm(
            ReadOnlySpan<byte> payload,
            uint acoreRealmId,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (payload.Length < AuthResponseReplayTopVirtualRealmAddressOffset + sizeof(uint))
            {
                error = $"AUTH_RESPONSE replay payload too short for top VirtualRealmAddress patch: len={payload.Length}, required={AuthResponseReplayTopVirtualRealmAddressOffset + sizeof(uint)}.";
                return false;
            }

            if ((payload[AuthResponseReplayOptionalBitsOffset] & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            patchedPayload = payload.ToArray();
            uint runtimeRealmAddress = BuildRuntimeVirtualRealmAddress(acoreRealmId);
            BinaryPrimitives.WriteUInt32LittleEndian(
                patchedPayload.AsSpan(AuthResponseReplayTopVirtualRealmAddressOffset, sizeof(uint)),
                runtimeRealmAddress);
            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadExpansionLevelsFromAcoreAccount(
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> acPayload,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (payload.Length < AuthResponseReplayAccountExpansionLevelOffset + sizeof(byte))
            {
                error = $"AUTH_RESPONSE replay payload too short for expansion-level patch: len={payload.Length}, required={AuthResponseReplayAccountExpansionLevelOffset + sizeof(byte)}.";
                return false;
            }

            if ((payload[AuthResponseReplayOptionalBitsOffset] & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            byte accountExpansion = ResolveAcoreAccountExpansionLevel(acPayload);
            patchedPayload = payload.ToArray();
            patchedPayload[AuthResponseReplayActiveExpansionLevelOffset] = accountExpansion;
            patchedPayload[AuthResponseReplayAccountExpansionLevelOffset] = accountExpansion;
            return true;
        }

        private static bool TryLocateAuthResponseReplaySuccessInfoOptionalFlagsOffset(
            ReadOnlySpan<byte> payload,
            out int optionalFlagsOffset,
            out string? error)
        {
            optionalFlagsOffset = 0;
            error = null;

            if (payload.Length < AuthResponseReplayClassMatrixStartOffset)
            {
                error = $"AUTH_RESPONSE replay payload too short for SuccessInfo optional-flags scan: len={payload.Length}, required>={AuthResponseReplayClassMatrixStartOffset}.";
                return false;
            }

            if ((payload[AuthResponseReplayOptionalBitsOffset] & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            if (payload.Length < AuthResponseReplayAvailableClassesCountOffset + sizeof(uint))
            {
                error = $"AUTH_RESPONSE replay payload too short for AvailableClasses count: len={payload.Length}, required={AuthResponseReplayAvailableClassesCountOffset + sizeof(uint)}.";
                return false;
            }

            uint availableClassesCount = BinaryPrimitives.ReadUInt32LittleEndian(
                payload.Slice(AuthResponseReplayAvailableClassesCountOffset, sizeof(uint)));
            if (availableClassesCount > AuthResponseReplayMaxAvailableClassesRows)
            {
                error = $"AUTH_RESPONSE replay payload AvailableClasses count is out of range: {availableClassesCount}.";
                return false;
            }

            int cursor = AuthResponseReplayClassMatrixStartOffset;
            for (uint raceIndex = 0; raceIndex < availableClassesCount; raceIndex++)
            {
                if (cursor + 1 + sizeof(uint) > payload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated before race row {raceIndex}: cursor={cursor}, len={payload.Length}.";
                    return false;
                }

                uint classCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(cursor + 1, sizeof(uint)));
                if (classCount > AuthResponseReplayMaxClassRowsPerRace)
                {
                    error = $"AUTH_RESPONSE replay payload class count is out of range at race row {raceIndex}: {classCount}.";
                    return false;
                }

                cursor += 1 + sizeof(uint);
                int classBytes = checked((int)classCount * 4);
                if (cursor + classBytes > payload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated at race row {raceIndex}: cursor={cursor}, classBytes={classBytes}, len={payload.Length}.";
                    return false;
                }

                cursor += classBytes;
            }

            if (cursor + 1 > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated at SuccessInfo optional flags byte: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            optionalFlagsOffset = cursor;
            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadCurrentBuildPresent(
            ReadOnlySpan<byte> payload,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (!TryLocateAuthResponseReplaySuccessInfoOptionalFlagsOffset(
                    payload,
                    out int optionalFlagsOffset,
                    out error))
            {
                return false;
            }

            int currentBuildOffset = optionalFlagsOffset + 1;
            bool currentBuildPresent = (payload[optionalFlagsOffset] & AuthResponseReplaySuccessInfoCurrentBuildMask) != 0;

            if (currentBuildPresent)
            {
                if (currentBuildOffset + sizeof(uint) > payload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated at CurrentBuild field: offset={currentBuildOffset}, len={payload.Length}.";
                    return false;
                }

                patchedPayload = payload.ToArray();
                BinaryPrimitives.WriteUInt32LittleEndian(
                    patchedPayload.AsSpan(currentBuildOffset, sizeof(uint)),
                    AuthResponseReplayCurrentBuildValue);
                return true;
            }

            patchedPayload = GC.AllocateUninitializedArray<byte>(payload.Length + sizeof(uint));

            payload[..(optionalFlagsOffset + 1)].CopyTo(patchedPayload.AsSpan(0, optionalFlagsOffset + 1));
            patchedPayload[optionalFlagsOffset] = (byte)(patchedPayload[optionalFlagsOffset] | AuthResponseReplaySuccessInfoCurrentBuildMask);
            BinaryPrimitives.WriteUInt32LittleEndian(
                patchedPayload.AsSpan(currentBuildOffset, sizeof(uint)),
                AuthResponseReplayCurrentBuildValue);
            payload[currentBuildOffset..].CopyTo(patchedPayload.AsSpan(currentBuildOffset + sizeof(uint)));
            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadWaitInfoPresent(
            ReadOnlySpan<byte> payload,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (payload.Length <= AuthResponseReplayOptionalBitsOffset)
            {
                error = $"AUTH_RESPONSE replay payload too short for top-level optional bits patch: len={payload.Length}, required>{AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            byte optionalBits = payload[AuthResponseReplayOptionalBitsOffset];
            if ((optionalBits & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            if ((optionalBits & AuthResponseReplayWaitInfoMask) != 0)
            {
                patchedPayload = payload.ToArray();
                return true;
            }

            patchedPayload = GC.AllocateUninitializedArray<byte>(payload.Length + AuthResponseReplayWaitInfoPayloadBytes);
            payload.CopyTo(patchedPayload);
            patchedPayload[AuthResponseReplayOptionalBitsOffset] =
                (byte)(patchedPayload[AuthResponseReplayOptionalBitsOffset] | AuthResponseReplayWaitInfoMask);
            patchedPayload.AsSpan(payload.Length, AuthResponseReplayWaitInfoPayloadBytes).Clear();
            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadVirtualRealmEntryFromRuntimeRealm(
            ReadOnlySpan<byte> payload,
            uint acoreRealmId,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (!TryLocateAuthResponseReplaySuccessInfoOptionalFlagsOffset(
                    payload,
                    out int optionalFlagsOffset,
                    out error))
            {
                return false;
            }

            int cursor = optionalFlagsOffset + 1;
            bool currentBuildPresent = (payload[optionalFlagsOffset] & AuthResponseReplaySuccessInfoCurrentBuildMask) != 0;
            if (currentBuildPresent)
            {
                if (cursor + sizeof(uint) > payload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated at CurrentBuild field: cursor={cursor}, len={payload.Length}.";
                    return false;
                }

                cursor += sizeof(uint);
            }

            // GameTimeInfo fixed fields + flushed optional bits byte.
            const int GameTimeFixedBytes = 12;
            const int GameTimeFlagsBytes = 1;
            if (cursor + GameTimeFixedBytes + GameTimeFlagsBytes > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated at GameTimeInfo block: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            cursor += GameTimeFixedBytes + GameTimeFlagsBytes;

            if (cursor + sizeof(uint) > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload truncated before VirtualRealmInfo.RealmAddress: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            patchedPayload = payload.ToArray();
            uint runtimeRealmAddress = BuildRuntimeVirtualRealmAddress(acoreRealmId);
            BinaryPrimitives.WriteUInt32LittleEndian(
                patchedPayload.AsSpan(cursor, sizeof(uint)),
                runtimeRealmAddress);

            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadClassMatrixCardinalityToRuntimeSubset(
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> acPayload,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (payload.Length < AuthResponseReplayClassMatrixStartOffset)
            {
                error = $"AUTH_RESPONSE replay payload too short for class-matrix cardinality patch: len={payload.Length}, required>={AuthResponseReplayClassMatrixStartOffset}.";
                return false;
            }

            if ((payload[AuthResponseReplayOptionalBitsOffset] & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            if (payload.Length < AuthResponseReplayAvailableClassesCountOffset + sizeof(uint))
            {
                error = $"AUTH_RESPONSE replay payload too short for AvailableClasses count: len={payload.Length}, required={AuthResponseReplayAvailableClassesCountOffset + sizeof(uint)}.";
                return false;
            }

            uint availableClassesCount = BinaryPrimitives.ReadUInt32LittleEndian(
                payload.Slice(AuthResponseReplayAvailableClassesCountOffset, sizeof(uint)));
            if (availableClassesCount > AuthResponseReplayMaxAvailableClassesRows)
            {
                error = $"AUTH_RESPONSE replay payload AvailableClasses count is out of range: {availableClassesCount}.";
                return false;
            }

            byte accountExpansion = ResolveAcoreAccountExpansionLevel(acPayload);
            int cursor = AuthResponseReplayClassMatrixStartOffset;
            var rewrittenMatrix = new List<byte>(Math.Max(256, payload.Length - AuthResponseReplayClassMatrixStartOffset));
            uint keptRaceRows = 0;

            for (uint raceIndex = 0; raceIndex < availableClassesCount; raceIndex++)
            {
                if (cursor + 1 + sizeof(uint) > payload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated before race row {raceIndex}: cursor={cursor}, len={payload.Length}.";
                    return false;
                }

                byte raceId = payload[cursor];
                uint classCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(cursor + 1, sizeof(uint)));
                if (classCount > AuthResponseReplayMaxClassRowsPerRace)
                {
                    error = $"AUTH_RESPONSE replay payload class count is out of range at race row {raceIndex}: {classCount}.";
                    return false;
                }

                cursor += 1 + sizeof(uint);

                int raceRowStart = rewrittenMatrix.Count;
                rewrittenMatrix.Add(raceId);
                rewrittenMatrix.Add(0);
                rewrittenMatrix.Add(0);
                rewrittenMatrix.Add(0);
                rewrittenMatrix.Add(0);

                uint keptClassRows = 0;
                for (uint classIndex = 0; classIndex < classCount; classIndex++)
                {
                    if (cursor + 4 > payload.Length)
                    {
                        error = $"AUTH_RESPONSE replay payload truncated at race row {raceIndex}, class row {classIndex}: cursor={cursor}, len={payload.Length}.";
                        return false;
                    }

                    byte classId = payload[cursor];
                    if (IsClassAllowedForExpansion(classId, accountExpansion))
                    {
                        rewrittenMatrix.Add(payload[cursor]);
                        rewrittenMatrix.Add(payload[cursor + 1]);
                        rewrittenMatrix.Add(payload[cursor + 2]);
                        rewrittenMatrix.Add(payload[cursor + 3]);
                        keptClassRows++;
                    }

                    cursor += 4;
                }

                if (keptClassRows == 0)
                {
                    rewrittenMatrix.RemoveRange(raceRowStart, rewrittenMatrix.Count - raceRowStart);
                    continue;
                }

                rewrittenMatrix[raceRowStart + 1] = (byte)(keptClassRows & 0xFFu);
                rewrittenMatrix[raceRowStart + 2] = (byte)((keptClassRows >> 8) & 0xFFu);
                rewrittenMatrix[raceRowStart + 3] = (byte)((keptClassRows >> 16) & 0xFFu);
                rewrittenMatrix[raceRowStart + 4] = (byte)((keptClassRows >> 24) & 0xFFu);
                keptRaceRows++;
            }

            if (cursor > payload.Length)
            {
                error = $"AUTH_RESPONSE replay payload class-matrix cursor overrun: cursor={cursor}, len={payload.Length}.";
                return false;
            }

            int suffixLength = payload.Length - cursor;
            patchedPayload = GC.AllocateUninitializedArray<byte>(
                AuthResponseReplayClassMatrixStartOffset + rewrittenMatrix.Count + suffixLength);

            payload[..AuthResponseReplayClassMatrixStartOffset].CopyTo(patchedPayload);
            BinaryPrimitives.WriteUInt32LittleEndian(
                patchedPayload.AsSpan(AuthResponseReplayAvailableClassesCountOffset, sizeof(uint)),
                keptRaceRows);

            for (int i = 0; i < rewrittenMatrix.Count; i++)
            {
                patchedPayload[AuthResponseReplayClassMatrixStartOffset + i] = rewrittenMatrix[i];
            }

            payload[cursor..].CopyTo(
                patchedPayload.AsSpan(AuthResponseReplayClassMatrixStartOffset + rewrittenMatrix.Count, suffixLength));

            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadClassMatrixExpansionTripletsFromAcoreAccount(
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> acPayload,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (payload.Length < AuthResponseReplayClassMatrixStartOffset)
            {
                error = $"AUTH_RESPONSE replay payload too short for class-matrix patch: len={payload.Length}, required>={AuthResponseReplayClassMatrixStartOffset}.";
                return false;
            }

            if ((payload[AuthResponseReplayOptionalBitsOffset] & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            if (payload.Length < AuthResponseReplayAvailableClassesCountOffset + sizeof(uint))
            {
                error = $"AUTH_RESPONSE replay payload too short for AvailableClasses count: len={payload.Length}, required={AuthResponseReplayAvailableClassesCountOffset + sizeof(uint)}.";
                return false;
            }

            uint availableClassesCount = BinaryPrimitives.ReadUInt32LittleEndian(
                payload.Slice(AuthResponseReplayAvailableClassesCountOffset, sizeof(uint)));
            if (availableClassesCount > AuthResponseReplayMaxAvailableClassesRows)
            {
                error = $"AUTH_RESPONSE replay payload AvailableClasses count is out of range: {availableClassesCount}.";
                return false;
            }

            byte accountExpansion = ResolveAcoreAccountExpansionLevel(acPayload);
            patchedPayload = payload.ToArray();

            int cursor = AuthResponseReplayClassMatrixStartOffset;
            for (uint raceIndex = 0; raceIndex < availableClassesCount; raceIndex++)
            {
                if (cursor + 1 + sizeof(uint) > patchedPayload.Length)
                {
                    error = $"AUTH_RESPONSE replay payload truncated before race row {raceIndex}: cursor={cursor}, len={patchedPayload.Length}.";
                    return false;
                }

                uint classCount = BinaryPrimitives.ReadUInt32LittleEndian(
                    patchedPayload.AsSpan(cursor + 1, sizeof(uint)));
                if (classCount > AuthResponseReplayMaxClassRowsPerRace)
                {
                    error = $"AUTH_RESPONSE replay payload class count is out of range at race row {raceIndex}: {classCount}.";
                    return false;
                }

                cursor += 1 + sizeof(uint);

                for (uint classIndex = 0; classIndex < classCount; classIndex++)
                {
                    if (cursor + 4 > patchedPayload.Length)
                    {
                        error = $"AUTH_RESPONSE replay payload truncated at race row {raceIndex}, class row {classIndex}: cursor={cursor}, len={patchedPayload.Length}.";
                        return false;
                    }

                    patchedPayload[cursor + 1] = accountExpansion;
                    patchedPayload[cursor + 2] = accountExpansion;
                    patchedPayload[cursor + 3] = accountExpansion;
                    cursor += 4;
                }
            }

            return true;
        }

        private static bool TryPatchAuthResponseReplayPayloadTimeUnixNow(
            ReadOnlySpan<byte> payload,
            out byte[] patchedPayload,
            out string? error)
        {
            patchedPayload = Array.Empty<byte>();
            error = null;

            if (payload.Length < AuthResponseReplayTimeFieldOffset + sizeof(int))
            {
                error = $"AUTH_RESPONSE replay payload too short for time patch: len={payload.Length}, required={AuthResponseReplayTimeFieldOffset + sizeof(int)}.";
                return false;
            }

            if ((payload[AuthResponseReplayOptionalBitsOffset] & AuthResponseReplaySuccessInfoMask) == 0)
            {
                error = $"AUTH_RESPONSE replay payload does not expose SuccessInfo bit at offset {AuthResponseReplayOptionalBitsOffset}.";
                return false;
            }

            patchedPayload = payload.ToArray();
            int unixNow = checked((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            BinaryPrimitives.WriteInt32LittleEndian(
                patchedPayload.AsSpan(AuthResponseReplayTimeFieldOffset, sizeof(int)),
                unixNow);
            return true;
        }

        private void ResetFrameState()
        {
            _headerBytesRead = 0;
            _headerBytesExpected = 0;
            _currentOpcode = 0;
            _payloadBytesExpected = 0;
            _payloadBytesRead = 0;
        }

        private readonly record struct BufferedServerFrame(ushort Opcode, byte[] Payload);
    }

    private enum BootstrapFlushTriggerMode
    {
        Ack = 0,
        FirstClientPostAckNonAck = 1
    }

    private static BootstrapFlushTriggerMode ParseBootstrapFlushTriggerMode(string? value, out bool valid)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            valid = true;
            return BootstrapFlushTriggerMode.Ack;
        }

        string normalized = value.Trim().ToLowerInvariant();
        valid = true;
        return normalized switch
        {
            "ack" => BootstrapFlushTriggerMode.Ack,
            "first_client_post_ack_non_ack" => BootstrapFlushTriggerMode.FirstClientPostAckNonAck,
            "first-client-post-ack-non-ack" => BootstrapFlushTriggerMode.FirstClientPostAckNonAck,
            "firstclientpostacknonack" => BootstrapFlushTriggerMode.FirstClientPostAckNonAck,
            _ => ParseBootstrapFlushTriggerModeInvalid(out valid)
        };
    }

    private static BootstrapFlushTriggerMode ParseBootstrapFlushTriggerModeInvalid(out bool valid)
    {
        valid = false;
        return BootstrapFlushTriggerMode.Ack;
    }

    private bool ResolveEffectiveAckGate(out string source)
    {
        bool fallback = AckPolicyResolver.ResolveWaitForAckGate(
            _ackPolicyMode,
            _options.EnterEncryptedModeAckGateEnabled);

        if (_ackPolicyMode != AckPolicyMode.Auto)
        {
            source = $"policy:{_protocolOptions.AckPolicy}";
            return fallback;
        }

        if (TryResolveAckGateFromDecisionArtifact(
                _protocolOptions.AckPolicyDecisionPath,
                out bool gateFromArtifact,
                out string artifactPath))
        {
            source = $"artifact:{artifactPath}";
            return gateFromArtifact;
        }

        source = "config:WorldProxy.EnterEncryptedModeAckGateEnabled";
        return fallback;
    }

    private static bool TryResolveAckGateFromDecisionArtifact(
        string? decisionPath,
        out bool gate,
        out string resolvedPath)
    {
        gate = false;
        resolvedPath = string.Empty;

        if (string.IsNullOrWhiteSpace(decisionPath))
        {
            return false;
        }

        resolvedPath = Path.IsPathRooted(decisionPath)
            ? decisionPath
            : Path.Combine(WorldGatewayPathResolver.ResolveProjectRoot(), decisionPath);
        if (!File.Exists(resolvedPath))
        {
            return false;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(resolvedPath, Encoding.UTF8));
            JsonElement root = doc.RootElement;

            if (root.TryGetProperty("effective_ack_gate", out JsonElement effectiveAckElement) &&
                (effectiveAckElement.ValueKind == JsonValueKind.True || effectiveAckElement.ValueKind == JsonValueKind.False))
            {
                gate = effectiveAckElement.GetBoolean();
                return true;
            }

            if (root.TryGetProperty("recommended_ack_policy", out JsonElement recommendedPolicyElement) &&
                recommendedPolicyElement.ValueKind == JsonValueKind.String)
            {
                AckPolicyMode mode = AckPolicyResolver.Parse(recommendedPolicyElement.GetString());
                if (mode == AckPolicyMode.Gate)
                {
                    gate = true;
                    return true;
                }

                if (mode == AckPolicyMode.NonBlocking)
                {
                    gate = false;
                    return true;
                }
            }

            if (root.TryGetProperty("winner", out JsonElement winnerElement) &&
                winnerElement.ValueKind == JsonValueKind.String)
            {
                AckPolicyMode winnerMode = AckPolicyResolver.Parse(winnerElement.GetString());
                if (winnerMode == AckPolicyMode.Gate)
                {
                    gate = true;
                    return true;
                }

                if (winnerMode == AckPolicyMode.NonBlocking)
                {
                    gate = false;
                    return true;
                }
            }
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    private static bool TryParseFlexibleUInt32(string? value, out uint parsed)
    {
        parsed = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string input = value.Trim();
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(input.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed);
        }

        return uint.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
    }

    private static bool TryParseProbeDropDeferredOpcodes(string rawValue, HashSet<uint> destination, out string? error)
    {
        error = null;
        destination.Clear();

        string[] tokens = rawValue.Split(
            [',', ';', '|', ' '],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (tokens.Length == 0)
        {
            error = "empty opcode list";
            return false;
        }

        foreach (string token in tokens)
        {
            if (!TryParseFlexibleUInt32(token, out uint opcode))
            {
                error = $"invalid opcode token '{token}'";
                destination.Clear();
                return false;
            }

            destination.Add(opcode);
        }

        if (destination.Count == 0)
        {
            error = "no valid opcode tokens";
            return false;
        }

        return true;
    }

    private static IPAddress ParseBindAddress(string address)
    {
        if (string.IsNullOrWhiteSpace(address) ||
            address == "*" ||
            address == "0.0.0.0")
        {
            return IPAddress.Any;
        }

        if (address == "::" || address == "[::]")
        {
            return IPAddress.IPv6Any;
        }

        return IPAddress.Parse(address);
    }
}





