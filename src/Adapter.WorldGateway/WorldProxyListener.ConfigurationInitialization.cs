using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
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
}
