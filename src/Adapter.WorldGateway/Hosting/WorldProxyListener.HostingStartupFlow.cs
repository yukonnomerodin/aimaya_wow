using System.Linq;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void InitializeListenerAndLogStartupState()
    {
        (IPAddress bindAddress, bool resolvedAckGate, string ackGateSource) = StartListenerAndResolveStartupContext();
        LogStartupProbeWarnings();
        LogStartupSummary(bindAddress, resolvedAckGate, ackGateSource);
    }

    private (IPAddress BindAddress, bool ResolvedAckGate, string AckGateSource) StartListenerAndResolveStartupContext()
    {
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

        return (bindAddress, resolvedAckGate, ackGateSource);
    }

    private void LogStartupProbeWarnings()
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

    }

    private void LogStartupSummary(IPAddress bindAddress, bool resolvedAckGate, string ackGateSource)
    {
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
    }
}
