using System.Globalization;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private RetailPostAuthClientTranslator? EnsureRetailPostAuthClientTranslator(
        string direction,
        RetailPostAuthClientTranslator? retailPostAuthClientTranslator,
        WorldProxyBridgeState bridgeState,
        uint connectionId,
        string downstreamKey)
    {
        if (direction != "client->world" ||
            retailPostAuthClientTranslator is not null ||
            !bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt sendCrypt))
        {
            return retailPostAuthClientTranslator;
        }

        retailPostAuthClientTranslator = new RetailPostAuthClientTranslator(
            sendCrypt,
            bridgeState,
            strictStageEnforcement: _protocolOptions.StrictStageEnforcement,
            onLogDisconnect: reason =>
            {
                bridgeState.SetLogDisconnectReason(reason);
                if (ReconnectCooldownHelpers.TryArm(
                        _reconnectCooldownUntilByKey,
                        _options.ReconnectCooldownMs,
                        downstreamKey,
                        out long cooldownUntilUnixMs))
                {
                    _logger.LogInformation(
                        "[WorldProxy][ANTISPAM] Reconnect cooldown armed. DownstreamKey={DownstreamKey}, CooldownMs={CooldownMs}, Source={Source}, Reason={Reason}, UntilUnixMs={UntilUnixMs}",
                        downstreamKey,
                        _options.ReconnectCooldownMs,
                        "cmsg_log_disconnect",
                        reason.ToString(CultureInfo.InvariantCulture),
                        cooldownUntilUnixMs);
                }

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

        return retailPostAuthClientTranslator;
    }

    private AcorePostAuthServerTranslator? EnsureAcorePostAuthServerTranslator(
        string direction,
        AcorePostAuthServerTranslator? acorePostAuthServerTranslator,
        WorldProxyBridgeState bridgeState,
        uint connectionId,
        bool waitForEnterEncryptedAckGate,
        Action<ushort, int> onFrameDecoded)
    {
        if (direction != "world->client" ||
            acorePostAuthServerTranslator is not null ||
            !bridgeState.TryGetAcoreHeaderCrypt(out AuthCrypt recvCrypt))
        {
            return acorePostAuthServerTranslator;
        }

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
            onFrameDecoded: onFrameDecoded,
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

        return acorePostAuthServerTranslator;
    }
}
