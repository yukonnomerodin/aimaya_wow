using System;
using System.Buffers;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
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
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
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
                        PostAuthTranslationHelpers.TryBuildControlledUnlockEmptyCharEnumFrame(
                            payload,
                            RetailOpcodeSmsgEnumCharactersResult,
                            out byte[] unlockedMapped))
                    {
                        mapped = unlockedMapped;
                        _onControlledUnlockApplied?.Invoke(payload.Length, Math.Max(0, mapped.Length - 20));
                    }

                    if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out long charEnumBytes, out error))
                    {
                        return false;
                    }

                    bytesWritten += charEnumBytes;
                    wroteCharEnumToClient = true;
                    _onCharEnumReceived?.Invoke();

                    if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                            _bridgeState,
                            RetailGluePayloadBuilders.BuildAccountItemCollectionDataFrame(RetailOpcodeSmsgAccountItemCollectionData),
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
                        if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                                _bridgeState,
                                RetailGluePayloadBuilders.BuildSocialContractRequestResponseFrame(
                                    RetailOpcodeSmsgSocialContractRequestResponse,
                                    showSocialContract: false),
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
                        if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                                _bridgeState,
                                RetailGluePayloadBuilders.BuildUndeleteCooldownStatusResponseFrame(
                                    RetailOpcodeSmsgUndeleteCooldownStatusResponse,
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
                        if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                                _bridgeState,
                                RetailGluePayloadBuilders.BuildHotfixConnectFrame(RetailOpcodeSmsgHotfixConnect),
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
                        if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                                _bridgeState,
                                RetailGluePayloadBuilders.BuildBattleNetResponseFrame(
                                    RetailOpcodeSmsgBattleNetResponse,
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
                        if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                                _bridgeState,
                                RetailGluePayloadBuilders.BuildServerTimeOffsetFrame(
                                    RetailOpcodeSmsgServerTimeOffset,
                                    DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
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
                            if (!PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(
                                    _bridgeState,
                                    RetailGluePayloadBuilders.BuildDbReplyFrame(
                                        RetailOpcodeSmsgDbReply,
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
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgWardenData)
            {
                if (_forwardAcoreWardenAsRetailWarden3Data)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgWarden3Data, payload);
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
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
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
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
                return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
            }

            if (opcode == AcoreOpcodeSmsgTutorialFlags)
            {
                if (_forwardAcoreTutorialFlagsAsRetailTutorialFlags)
                {
                    byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(RetailOpcodeSmsgTutorialFlags, payload);
                    return PostAuthServerFrameWriteHelpers.TryWriteProtectedRetailServerFrame(_bridgeState, mapped, output, out bytesWritten, out error);
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
    }
}
