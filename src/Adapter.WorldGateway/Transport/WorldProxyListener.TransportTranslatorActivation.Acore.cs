using System;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
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
