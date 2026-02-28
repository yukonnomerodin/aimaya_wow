using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class RetailPostAuthClientTranslator
    {
        public RetailPostAuthClientTranslator(
            AuthCrypt authCrypt,
            WorldProxyBridgeState bridgeState,
            bool strictStageEnforcement = true,
            Action<uint>? onLogDisconnect = null,
            Action? onEnumCharactersRequest = null,
            Action? onEnterEncryptedModeAck = null,
            Action<uint>? onPostAckNonAckClientFrame = null,
            int glueSyntheticCharEnumKickMinIntervalMs = 0,
            Action<uint, int>? onGlueSyntheticKickSuppressed = null)
        {
            _authCrypt = authCrypt ?? throw new ArgumentNullException(nameof(authCrypt));
            _bridgeState = bridgeState ?? throw new ArgumentNullException(nameof(bridgeState));
            _strictStageEnforcement = strictStageEnforcement;
            _onLogDisconnect = onLogDisconnect;
            _onEnumCharactersRequest = onEnumCharactersRequest;
            _onEnterEncryptedModeAck = onEnterEncryptedModeAck;
            _onPostAckNonAckClientFrame = onPostAckNonAckClientFrame;
            _glueSyntheticCharEnumKickMinIntervalMs = Math.Clamp(glueSyntheticCharEnumKickMinIntervalMs, 0, 5000);
            _onGlueSyntheticKickSuppressed = onGlueSyntheticKickSuppressed;
        }

        public bool TryTransform(
            ReadOnlySequence<byte> input,
            IBufferWriter<byte> output,
            Action<uint, int>? onDroppedOpcode,
            out long bytesWritten,
            out string? error)
        {
            bytesWritten = 0;
            error = null;

            foreach (ReadOnlyMemory<byte> segment in input)
            {
                ReadOnlySpan<byte> span = segment.Span;
                int offset = 0;
                while (offset < span.Length)
                {
                    if (_frameExpectedBytes == 0)
                    {
                        int needPrefix = 4 - _sizePrefixRead;
                        int takePrefix = Math.Min(needPrefix, span.Length - offset);
                        span.Slice(offset, takePrefix).CopyTo(_sizePrefix.AsSpan(_sizePrefixRead, takePrefix));
                        _sizePrefixRead += takePrefix;
                        offset += takePrefix;

                        if (_sizePrefixRead < 4)
                        {
                            continue;
                        }

                        uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(_sizePrefix);
                        if (packetSize < WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
                        {
                            error = $"Invalid Retail frame size field (<4): {packetSize}.";
                            return false;
                        }

                        _frameExpectedBytes = checked((int)packetSize + WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes);
                        if (_frameExpectedBytes < WorldGatewayProtocolConstants.RetailWorldFrameMinBytes ||
                            _frameExpectedBytes > WorldGatewayProtocolConstants.RetailPostAuthClientMaxFrameBytes)
                        {
                            error = $"Invalid Retail frame size (bytes): {_frameExpectedBytes}.";
                            return false;
                        }

                        if (_frameBuffer.Length < _frameExpectedBytes)
                        {
                            _frameBuffer = GC.AllocateUninitializedArray<byte>(_frameExpectedBytes);
                        }

                        _sizePrefix.AsSpan().CopyTo(_frameBuffer.AsSpan(0, 4));
                        _frameBytesRead = 4;
                        _sizePrefixRead = 0;
                    }

                    int remaining = _frameExpectedBytes - _frameBytesRead;
                    int take = Math.Min(remaining, span.Length - offset);
                    span.Slice(offset, take).CopyTo(_frameBuffer.AsSpan(_frameBytesRead, take));
                    _frameBytesRead += take;
                    offset += take;

                    if (_frameBytesRead < _frameExpectedBytes)
                    {
                        continue;
                    }

                    if (!TryTranslateFrame(_frameBuffer.AsSpan(0, _frameExpectedBytes), output, onDroppedOpcode, out long frameBytes, out error))
                    {
                        return false;
                    }

                    bytesWritten += frameBytes;
                    _frameExpectedBytes = 0;
                    _frameBytesRead = 0;
                }
            }

            return true;
        }

        private bool TryTranslateFrame(
            ReadOnlySpan<byte> retailFrame,
            IBufferWriter<byte> output,
            Action<uint, int>? onDroppedOpcode,
            out long bytesWritten,
            out string? error)
        {
            bytesWritten = 0;
            error = null;

            if (retailFrame.Length < WorldGatewayProtocolConstants.RetailWorldFrameMinBytes)
            {
                error = $"Retail frame is too short: {retailFrame.Length}.";
                return false;
            }

            if (!_bridgeState.TryDecryptRetailClientFrame(retailFrame, out byte[] decryptedFrame, out string? decryptError))
            {
                error = $"Failed to decode Retail client world frame: {decryptError ?? "<unknown>"}";
                return false;
            }

            ReadOnlySpan<byte> effectiveFrame = decryptedFrame;

            uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(effectiveFrame[..4]);
            int expectedFrameBytes = checked((int)packetSize + WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes);
            if (effectiveFrame.Length != expectedFrameBytes || packetSize < WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
            {
                error = $"Retail frame size mismatch. PacketSize={packetSize}, FrameBytes={effectiveFrame.Length}, Expected={expectedFrameBytes}.";
                return false;
            }

            uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(
                effectiveFrame.Slice(
                    WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes,
                    WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
            int payloadBytes = (int)packetSize - WorldGatewayProtocolConstants.RetailWorldOpcodeBytes;
            ReadOnlySpan<byte> payload = effectiveFrame.Slice(
                WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes,
                payloadBytes);

            if (!_bridgeState.ValidateClientOpcode(opcode, _strictStageEnforcement, out string? stageError))
            {
                error = stageError;
                return false;
            }

            if (opcode != WorldGatewayOpcodes.RetailCmsgEnterEncryptedModeAck && _bridgeState.AckObserved)
            {
                _onPostAckNonAckClientFrame?.Invoke(opcode);
            }

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

            if (_loggedDroppedOpcodes.Add(opcode))
            {
                onDroppedOpcode?.Invoke(opcode, payloadBytes);
            }

            return true;
        }

        private bool TryKickGlueResponseTurn(IBufferWriter<byte> output, uint triggerOpcode, out long bytesWritten)
        {
            bytesWritten = 0;

            bool bypassThrottle = triggerOpcode == WorldGatewayOpcodes.RetailCmsgDbQueryBulk ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgBattlenetRequest ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgServerTimeOffsetRequest ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgHotfixRequest ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgBattlePayGetPurchaseList ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgBattlePayGetProductList ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgUpdateVasPurchaseStates ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgQuickJoinAutoAcceptRequests ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgGetLastCatalogFetch ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgSocialContractRequest ||
                                  triggerOpcode == WorldGatewayOpcodes.RetailCmsgGetUndeleteCharacterCooldownStatus;

            if (!bypassThrottle &&
                _glueSyntheticCharEnumKickMinIntervalMs > 0 &&
                _lastGlueSyntheticKickUnixMs != long.MinValue)
            {
                long nowUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                long elapsedMs = nowUnixMs - _lastGlueSyntheticKickUnixMs;
                if (elapsedMs >= 0 && elapsedMs < _glueSyntheticCharEnumKickMinIntervalMs)
                {
                    int waitMs = checked((int)(_glueSyntheticCharEnumKickMinIntervalMs - elapsedMs));
                    _onGlueSyntheticKickSuppressed?.Invoke(triggerOpcode, waitMs);
                    return true;
                }
            }

            if (!_bridgeState.TryArmPendingGlueKick())
            {
                return true;
            }

            bool forwarded = PostAuthClientFrameForwardingHelpers.TryWriteEncryptedAcoreClientFrame(
                _authCrypt,
                WorldGatewayOpcodes.AcoreCmsgCharEnum,
                ReadOnlySpan<byte>.Empty,
                output,
                out bytesWritten);
            if (forwarded)
            {
                _lastGlueSyntheticKickUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            }

            return forwarded;
        }

    }

}
