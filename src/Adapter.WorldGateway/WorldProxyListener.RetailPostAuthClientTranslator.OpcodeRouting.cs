using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class RetailPostAuthClientTranslator
    {
        private bool TryHandleKnownOpcode(
            uint opcode,
            ReadOnlySpan<byte> payload,
            int payloadBytes,
            IBufferWriter<byte> output,
            Action<uint, int>? onDroppedOpcode,
            out bool handled,
            out long bytesWritten,
            out string? error)
        {
            handled = true;
            bytesWritten = 0;
            error = null;

            if (opcode == WorldGatewayOpcodes.RetailCmsgPing)
            {
                if (payloadBytes < 8)
                {
                    error = $"Retail CMSG_PING payload too short: {payloadBytes}.";
                    return false;
                }

                return PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                    _authCrypt,
                    WorldGatewayOpcodes.AcoreCmsgPing,
                    payload[..8],
                    output,
                    out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgEnterEncryptedModeAck)
            {
                // Retail world stage ack for SMSG_ENTER_ENCRYPTED_MODE.
                // No AC equivalent in 3.3.5 bridge mode.
                _onEnterEncryptedModeAck?.Invoke();
                return true;
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgEnumCharacters)
            {
                _onEnumCharactersRequest?.Invoke();
                return PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                    _authCrypt,
                    WorldGatewayOpcodes.AcoreCmsgCharEnum,
                    ReadOnlySpan<byte>.Empty,
                    output,
                    out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgWarden3Data)
            {
                return PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                    _authCrypt,
                    WorldGatewayOpcodes.AcoreCmsgWardenData,
                    payload,
                    output,
                    out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgGetUndeleteCharacterCooldownStatus)
            {
                _bridgeState.MarkPendingUndeleteCooldownStatusRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgSocialContractRequest)
            {
                _bridgeState.MarkPendingSocialContractRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgDbQueryBulk)
            {
                if (RetailGlueRequestParsers.TryParseDbQueryBulk(payload, out ParsedDbQueryBulk query, out _))
                {
                    _bridgeState.EnqueuePendingDbQueryBulkReplies(query.TableHash, query.RecordIds);
                }
                else if (_loggedDroppedOpcodes.Add(opcode))
                {
                    onDroppedOpcode?.Invoke(opcode, payloadBytes);
                }

                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgHotfixRequest)
            {
                _bridgeState.MarkPendingHotfixRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgServerTimeOffsetRequest)
            {
                _bridgeState.MarkPendingServerTimeOffsetRequest();
                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgBattlenetRequest)
            {
                if (RetailGlueRequestParsers.TryParseBattlenetRequest(payload, out ParsedBattlenetRequest request, out _))
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

            if (opcode == WorldGatewayOpcodes.RetailCmsgBattlePayGetPurchaseList ||
                opcode == WorldGatewayOpcodes.RetailCmsgBattlePayGetProductList ||
                opcode == WorldGatewayOpcodes.RetailCmsgUpdateVasPurchaseStates ||
                opcode == WorldGatewayOpcodes.RetailCmsgQuickJoinAutoAcceptRequests ||
                opcode == WorldGatewayOpcodes.RetailCmsgGetLastCatalogFetch)
            {
                if (_bridgeState.CurrentStage >= BridgeStage.CHAR_ENUM_RECEIVED)
                {
                    // After first char-enum is already delivered, these glue opcodes are noise
                    // (TC commonly ignores them). Do not trigger extra synthetic enum turns.
                    return true;
                }

                return TryKickGlueResponseTurn(output, opcode, out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgAddonList)
            {
                // AC receives addon metadata inside CMSG_AUTH_SESSION payload.
                // Ignore standalone Retail addon list packets in bridge mode.
                return true;
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgKeepAlive)
            {
                return PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                    _authCrypt,
                    WorldGatewayOpcodes.AcoreCmsgKeepAlive,
                    ReadOnlySpan<byte>.Empty,
                    output,
                    out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgTimeSyncResponse)
            {
                if (payloadBytes < 8)
                {
                    error = $"Retail CMSG_TIME_SYNC_RESPONSE payload too short: {payloadBytes}.";
                    return false;
                }

                return PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                    _authCrypt,
                    WorldGatewayOpcodes.AcoreCmsgTimeSyncResp,
                    payload[..8],
                    output,
                    out bytesWritten);
            }

            if (opcode == WorldGatewayOpcodes.RetailCmsgLogDisconnect)
            {
                if (payloadBytes >= 4)
                {
                    _onLogDisconnect?.Invoke(BinaryPrimitives.ReadUInt32LittleEndian(payload[..4]));
                }

                // Client is terminating world session; nothing to forward to AC in 3.3.5 bridge mode.
                return true;
            }

            handled = false;
            return true;
        }
    }
}
