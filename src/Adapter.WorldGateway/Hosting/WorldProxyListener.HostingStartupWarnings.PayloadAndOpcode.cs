using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void LogStartupProbePayloadAndOpcodeWarnings()
    {
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
    }
}
