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
        ParsedOptionInitializationResult parsedOptionInitialization = ParseOptionInitialization(_options, _protocolOptions);
        _ackPolicyMode = parsedOptionInitialization.AckPolicyMode;
        _bootstrapFlushTriggerMode = parsedOptionInitialization.BootstrapFlushTriggerMode;
        _bootstrapFlushTriggerModeValid = parsedOptionInitialization.BootstrapFlushTriggerModeValid;
        _enterEncryptedModeOpcode = parsedOptionInitialization.EnterEncryptedModeOpcode;
        _enterEncryptedModeOpcodeValid = parsedOptionInitialization.EnterEncryptedModeOpcodeValid;
        _probeAuthResponseOpcode = parsedOptionInitialization.ProbeAuthResponseOpcode;
        _probeAuthResponseOpcodeOverrideProvided = parsedOptionInitialization.ProbeAuthResponseOpcodeOverrideProvided;
        _probeAuthResponseOpcodeOverrideValid = parsedOptionInitialization.ProbeAuthResponseOpcodeOverrideValid;
        _authResponseFuzzMutation = parsedOptionInitialization.AuthResponseFuzzMutation;
        _authResponseFuzzPlanRecognized = parsedOptionInitialization.AuthResponseFuzzPlanRecognized;
        _probeDropDeferredOpcodeConfigProvided = parsedOptionInitialization.ProbeDropDeferredOpcodeConfigProvided;
        _probeDropDeferredOpcodeParseError = parsedOptionInitialization.ProbeDropDeferredOpcodeParseError;
        foreach (uint dropOpcode in parsedOptionInitialization.ProbeDropDeferredOpcodes)
        {
            _probeDropDeferredOpcodes.Add(dropOpcode);
        }

        ProbeFixedHexPayloadLoadResult preludePayloadLoad = LoadOptionalFixedLengthHexPayload(
            _options.ProbeRetailSequencePreludePayloadHex,
            expectedLengthBytes: 4,
            defaultPayload: _probeRetailSequencePreludePayload);
        _probeRetailSequencePreludePayloadProvided = preludePayloadLoad.Provided;
        _probeRetailSequencePreludePayloadValid = preludePayloadLoad.Valid;
        _probeRetailSequencePreludePayload = preludePayloadLoad.Payload;
        _probeRetailSequencePreludePayloadParseError = preludePayloadLoad.Error;

        ProbeFileHexPayloadLoadResult authResponseReplayPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeAuthResponseReplayPayloadHexPath);
        _probeAuthResponseReplayPayloadProvided = authResponseReplayPayloadLoad.Provided;
        _probeAuthResponseReplayPayloadValid = authResponseReplayPayloadLoad.Valid;
        _probeAuthResponseReplayPayload = authResponseReplayPayloadLoad.Payload;
        _probeAuthResponseReplayPayloadParseError = authResponseReplayPayloadLoad.Error;
        _probeAuthResponseReplayPayloadResolvedPath = authResponseReplayPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult authResponseReplayCompressedPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeAuthResponseReplayCompressedPayloadHexPath);
        _probeAuthResponseReplayCompressedPayloadProvided = authResponseReplayCompressedPayloadLoad.Provided;
        _probeAuthResponseReplayCompressedPayloadValid = authResponseReplayCompressedPayloadLoad.Valid;
        _probeAuthResponseReplayCompressedPayload = authResponseReplayCompressedPayloadLoad.Payload;
        _probeAuthResponseReplayCompressedPayloadParseError = authResponseReplayCompressedPayloadLoad.Error;
        _probeAuthResponseReplayCompressedPayloadResolvedPath = authResponseReplayCompressedPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult timeZonePayloadLoad = LoadOptionalFileHexPayload(_options.ProbeSetTimeZoneInformationPayloadHexPath);
        _probeSetTimeZoneInformationPayloadProvided = timeZonePayloadLoad.Provided;
        _probeSetTimeZoneInformationPayloadValid = timeZonePayloadLoad.Valid;
        _probeSetTimeZoneInformationPayload = timeZonePayloadLoad.Payload;
        _probeSetTimeZoneInformationPayloadParseError = timeZonePayloadLoad.Error;
        _probeSetTimeZoneInformationPayloadResolvedPath = timeZonePayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult featurePayloadLoad = LoadOptionalFileHexPayload(_options.ProbeFeatureSystemStatusGlueScreenPayloadHexPath);
        _probeFeatureSystemStatusGlueScreenPayloadProvided = featurePayloadLoad.Provided;
        _probeFeatureSystemStatusGlueScreenPayloadValid = featurePayloadLoad.Valid;
        _probeFeatureSystemStatusGlueScreenPayload = featurePayloadLoad.Payload;
        _probeFeatureSystemStatusGlueScreenPayloadParseError = featurePayloadLoad.Error;
        _probeFeatureSystemStatusGlueScreenPayloadResolvedPath = featurePayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult mirrorVarsPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeMirrorVarsPayloadHexPath);
        _probeMirrorVarsPayloadProvided = mirrorVarsPayloadLoad.Provided;
        _probeMirrorVarsPayloadValid = mirrorVarsPayloadLoad.Valid;
        _probeMirrorVarsPayload = mirrorVarsPayloadLoad.Payload;
        _probeMirrorVarsPayloadParseError = mirrorVarsPayloadLoad.Error;
        _probeMirrorVarsPayloadResolvedPath = mirrorVarsPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult cacheVersionPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeCacheVersionPayloadHexPath);
        _probeCacheVersionPayloadProvided = cacheVersionPayloadLoad.Provided;
        _probeCacheVersionPayloadValid = cacheVersionPayloadLoad.Valid;
        _probeCacheVersionPayload = cacheVersionPayloadLoad.Payload;
        _probeCacheVersionPayloadParseError = cacheVersionPayloadLoad.Error;
        _probeCacheVersionPayloadResolvedPath = cacheVersionPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult availableHotfixesPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeAvailableHotfixesPayloadHexPath);
        _probeAvailableHotfixesPayloadProvided = availableHotfixesPayloadLoad.Provided;
        _probeAvailableHotfixesPayloadValid = availableHotfixesPayloadLoad.Valid;
        _probeAvailableHotfixesPayload = availableHotfixesPayloadLoad.Payload;
        _probeAvailableHotfixesPayloadParseError = availableHotfixesPayloadLoad.Error;
        _probeAvailableHotfixesPayloadResolvedPath = availableHotfixesPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult accountDataTimesPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeAccountDataTimesPayloadHexPath);
        _probeAccountDataTimesPayloadProvided = accountDataTimesPayloadLoad.Provided;
        _probeAccountDataTimesPayloadValid = accountDataTimesPayloadLoad.Valid;
        _probeAccountDataTimesPayload = accountDataTimesPayloadLoad.Payload;
        _probeAccountDataTimesPayloadParseError = accountDataTimesPayloadLoad.Error;
        _probeAccountDataTimesPayloadResolvedPath = accountDataTimesPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult tutorialFlagsPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeTutorialFlagsPayloadHexPath);
        _probeTutorialFlagsPayloadProvided = tutorialFlagsPayloadLoad.Provided;
        _probeTutorialFlagsPayloadValid = tutorialFlagsPayloadLoad.Valid;
        _probeTutorialFlagsPayload = tutorialFlagsPayloadLoad.Payload;
        _probeTutorialFlagsPayloadParseError = tutorialFlagsPayloadLoad.Error;
        _probeTutorialFlagsPayloadResolvedPath = tutorialFlagsPayloadLoad.ResolvedPath;

        ProbeFileHexPayloadLoadResult battleNetConnectionStatusPayloadLoad = LoadOptionalFileHexPayload(_options.ProbeBattleNetConnectionStatusPayloadHexPath);
        _probeBattleNetConnectionStatusPayloadProvided = battleNetConnectionStatusPayloadLoad.Provided;
        _probeBattleNetConnectionStatusPayloadValid = battleNetConnectionStatusPayloadLoad.Valid;
        _probeBattleNetConnectionStatusPayload = battleNetConnectionStatusPayloadLoad.Payload;
        _probeBattleNetConnectionStatusPayloadParseError = battleNetConnectionStatusPayloadLoad.Error;
        _probeBattleNetConnectionStatusPayloadResolvedPath = battleNetConnectionStatusPayloadLoad.ResolvedPath;
    }
}
