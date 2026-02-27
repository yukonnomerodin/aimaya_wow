using System;
using System.Buffers;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryHandleAfterAuthCharEnum(ReadOnlySpan<byte> payload, IBufferWriter<byte> output, ref long bytesWritten, out string? error)
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
                byte[] mapped = RetailEnvelopeBuilder.BuildRetailWorldFrame(WorldGatewayOpcodes.RetailSmsgEnumCharactersResult, payload);
                if (_controlledUnlockEmptyCharEnumEnabled &&
                    PostAuthTranslationHelpers.TryBuildControlledUnlockEmptyCharEnumFrame(
                        payload,
                        WorldGatewayOpcodes.RetailSmsgEnumCharactersResult,
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
                        RetailGluePayloadBuilders.BuildAccountItemCollectionDataFrame(WorldGatewayOpcodes.RetailSmsgAccountItemCollectionData),
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
                                WorldGatewayOpcodes.RetailSmsgSocialContractRequestResponse,
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
                                WorldGatewayOpcodes.RetailSmsgUndeleteCooldownStatusResponse,
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
                            RetailGluePayloadBuilders.BuildHotfixConnectFrame(WorldGatewayOpcodes.RetailSmsgHotfixConnect),
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
                                WorldGatewayOpcodes.RetailSmsgBattleNetResponse,
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
                                WorldGatewayOpcodes.RetailSmsgServerTimeOffset,
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
                                    WorldGatewayOpcodes.RetailSmsgDbReply,
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

            error = null;
            return true;
        }
    }
}