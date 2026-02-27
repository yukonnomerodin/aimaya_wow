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
public sealed partial class WorldProxyListener : BackgroundService
{
    private static readonly byte[] Sha1ZeroPrefix = [0, 0, 0, 0];
    private static readonly byte[] ServerConnectionInitializer = Encoding.ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2\n");
    private static readonly byte[] ClientConnectionInitializer = Encoding.ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2\n");
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
            WorldGatewayProtocolConstants.AcoreSessionKeyBytes,
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
        _bootstrapFlushTriggerMode = WorldProxyConfigParsers.ParseBootstrapFlushTriggerMode(
            _options.BootstrapFlushTriggerSource,
            out _bootstrapFlushTriggerModeValid);
        _enterEncryptedModeOpcodeValid = WorldProxyConfigParsers.TryParseFlexibleUInt32(_options.EnterEncryptedModeOpcode, out _enterEncryptedModeOpcode);
        _probeAuthResponseOpcode = WorldGatewayOpcodes.RetailSmsgAuthResponse;
        if (!_enterEncryptedModeOpcodeValid)
        {
            _enterEncryptedModeOpcode = WorldGatewayOpcodes.RetailSmsgEnterEncryptedModeDefault;
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeAuthResponseOpcodeOverride))
        {
            _probeAuthResponseOpcodeOverrideProvided = true;
            _probeAuthResponseOpcodeOverrideValid = WorldProxyConfigParsers.TryParseFlexibleUInt32(
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
            WorldGatewayOpcodes.RetailSmsgAuthResponseSweepStart,
            WorldGatewayOpcodes.RetailSmsgAuthResponseSweepCount,
            out _authResponseFuzzPlanRecognized);
        if (_authResponseFuzzMutation.Enabled && _authResponseFuzzMutation.OpcodeOverride is uint fuzzOpcode)
        {
            _probeAuthResponseOpcode = fuzzOpcode;
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeDropDeferredOpcode))
        {
            _probeDropDeferredOpcodeConfigProvided = true;
            if (!WorldProxyConfigParsers.TryParseProbeDropDeferredOpcodes(
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

        IPAddress bindAddress = WorldProxyConfigParsers.ParseBindAddress(_options.ListenAddress);
        bool resolvedAckGate = AckPolicyResolver.ResolveEffectiveWaitForAckGate(
            _ackPolicyMode,
            _options.EnterEncryptedModeAckGateEnabled,
            _protocolOptions.AckPolicy,
            _protocolOptions.AckPolicyDecisionPath,
            out string ackGateSource);
        _listener = new TcpListener(bindAddress, _options.ListenPort);
        _listener.Server.NoDelay = true;
        _listener.Start(_options.Backlog);

        if (!_enterEncryptedModeOpcodeValid)
        {
            _logger.LogWarning(
                "WorldProxy option EnterEncryptedModeOpcode is invalid ('{ConfiguredValue}'). Falling back to default 0x{DefaultOpcode:X8}.",
                _options.EnterEncryptedModeOpcode,
                WorldGatewayOpcodes.RetailSmsgEnterEncryptedModeDefault);
        }

        if (_probeAuthResponseOpcodeOverrideProvided && !_probeAuthResponseOpcodeOverrideValid)
        {
            _logger.LogWarning(
                "WorldProxy option ProbeAuthResponseOpcodeOverride is invalid ('{ConfiguredValue}'). Falling back to default 0x{DefaultOpcode:X8}.",
                _options.ProbeAuthResponseOpcodeOverride,
                WorldGatewayOpcodes.RetailSmsgAuthResponse);
        }

        if (_probeAuthResponseOpcode != WorldGatewayOpcodes.RetailSmsgAuthResponse)
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
                    WorldGatewayProtocolConstants.AuthResponseReplayTimeFieldOffset);
            }

            if (_probeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: AUTH_RESPONSE replay payload runtime patch active (Active/AccountExpansionLevel at payload offsets {ActiveOffset}/{AccountOffset} are overwritten from AC account expansion per frame).",
                    WorldGatewayProtocolConstants.AuthResponseReplayActiveExpansionLevelOffset,
                    WorldGatewayProtocolConstants.AuthResponseReplayAccountExpansionLevelOffset);
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
                    WorldGatewayProtocolConstants.AuthResponseReplayCurrentBuildValue);
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
                WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude,
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
                WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude,
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
                    WorldGatewayOpcodes.RetailSmsgAuthSequencePrelude);
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
                WorldGatewayProtocolConstants.TrinityCompressionThresholdBytes);

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
                RetailCompressionCodec.NormalizeChecksumSeed(
                    _options.ProbeCompressedAuthResponseChecksumSeed,
                    WorldGatewayProtocolConstants.TrinityCompressionAdlerSeed));
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

        if (!string.Equals(
                _options.RetailWorldPacketCryptNonceLayout,
                WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultNonceLayout,
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt nonce layout override active ({NonceLayout}).",
                _options.RetailWorldPacketCryptNonceLayout);
        }

        if (!string.Equals(
                _options.RetailWorldPacketCryptServerNonceMagic,
                WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultServerNonceMagic,
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt server nonce magic override active ({ServerNonceMagic}).",
                _options.RetailWorldPacketCryptServerNonceMagic);
        }

        if (!string.Equals(
                _options.RetailWorldPacketCryptClientNonceMagic,
                WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultClientNonceMagic,
                StringComparison.OrdinalIgnoreCase))
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
            await RunAcceptLoopAsync(stoppingToken).ConfigureAwait(false);
        }
        finally
        {
            await StopListenerAndAwaitActiveConnectionsAsync().ConfigureAwait(false);
        }
    }

}
