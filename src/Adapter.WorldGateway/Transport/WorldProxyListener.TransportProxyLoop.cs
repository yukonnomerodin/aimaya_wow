using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using MySqlConnector;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async Task<long> ProxyStreamAsync(
        uint connectionId,
        string direction,
        PipeReader reader,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        bool firstChunkDumped = false;
        bool firstAcoreChallengeBridged = false;
        bool firstRetailAuthSessionBridged = false;
        bool firstPostAuthDumpedClient = false;
        bool firstPostAuthDumpedServer = false;
        int acServerFramesLogged = 0;
        RetailPostAuthClientTranslator? retailPostAuthClientTranslator = null;
        AcorePostAuthServerTranslator? acorePostAuthServerTranslator = null;
        bool waitForEnterEncryptedAckGate = AckPolicyResolver.ResolveEffectiveWaitForAckGate(
            _ackPolicyMode,
            _options.EnterEncryptedModeAckGateEnabled,
            _protocolOptions.AckPolicy,
            _protocolOptions.AckPolicyDecisionPath,
            out _);

        while (!cancellationToken.IsCancellationRequested)
        {
            ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = readResult.Buffer;

            if (!buffer.IsEmpty)
            {
                if (_options.EnableFirstPacketDump && !firstChunkDumped)
                {
                    firstChunkDumped = true;
                    int maxBytes = _options.FirstPacketDumpBytes <= 0
                        ? WorldProxyRuntimeConstants.DefaultDumpBytes
                        : _options.FirstPacketDumpBytes;
                    _logger.LogInformation(
                        "[WorldProxy][DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(buffer, maxBytes));

                    if (RetailFrameCodec.TryDecodeFirstHeader(buffer, out DumpHeaderDecode decode))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][DUMP-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, FrameBytes={FrameBytes}, SizeBE={SizeBE}, SizeLE={SizeLE}, OpcodeLE=0x{OpcodeLE:X4}, OpcodeBE=0x{OpcodeBE:X4}, SizeBEMatches={SizeBEMatches}",
                            connectionId,
                            direction,
                            buffer.Length,
                            decode.SizeBE,
                            decode.SizeLE,
                            decode.OpcodeLE,
                            decode.OpcodeBE,
                            decode.SizeBEMatches);

                        if (direction == "world->client" &&
                            decode.OpcodeLE == WorldGatewayOpcodes.AcoreSmsgAuthChallenge &&
                            AcoreAuthChallengeDumpDecoder.TryDecode(buffer, out AcoreAuthChallengeDump challenge))
                        {
                            bridgeState.SetAcoreAuthSeed(challenge.AuthSeed);
                            bridgeState.SetAcoreServerChallenge(challenge.NewSeed);

                            _logger.LogInformation(
                                "[WorldProxy][DUMP-AC-AUTH-CHALLENGE] ConnectionId={ConnectionId}, DosChallenge={DosChallenge}, AuthSeed=0x{AuthSeed:X8}, NewSeed={NewSeedHex}",
                                connectionId,
                                challenge.DosChallenge,
                                challenge.AuthSeed,
                                challenge.NewSeedHex);
                        }
                    }
                }

                retailPostAuthClientTranslator = EnsureRetailPostAuthClientTranslator(
                    direction,
                    retailPostAuthClientTranslator,
                    bridgeState,
                    connectionId,
                    downstreamKey);

                acorePostAuthServerTranslator = EnsureAcorePostAuthServerTranslator(
                    direction,
                    acorePostAuthServerTranslator,
                    bridgeState,
                    connectionId,
                    waitForEnterEncryptedAckGate,
                    onFrameDecoded: (opcode, payloadBytes) =>
                    {
                        // Limit frame spam while collecting first handshake map.
                        if (acServerFramesLogged < 32)
                        {
                            acServerFramesLogged++;
                            _logger.LogInformation(
                                "[WorldProxy][AC->CLIENT FRAME] ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                                connectionId,
                                opcode,
                                payloadBytes);
                        }
                    });

                if (direction == "world->client" &&
                    !firstPostAuthDumpedServer &&
                    bridgeState.TryGetAcoreHeaderCrypt(out _))
                {
                    firstPostAuthDumpedServer = true;
                    _logger.LogInformation(
                        "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(
                            buffer,
                            Math.Max(WorldProxyRuntimeConstants.DefaultDumpBytes, _options.FirstPacketDumpBytes)));
                }

                if (direction == "client->world" &&
                    !firstPostAuthDumpedClient &&
                    bridgeState.TryGetAcoreHeaderCrypt(out _))
                {
                    firstPostAuthDumpedClient = true;
                    _logger.LogInformation(
                        "[WorldProxy][POSTAUTH-DUMP] ConnectionId={ConnectionId}, Direction={Direction}, Bytes={Bytes}, Head={Head}",
                        connectionId,
                        direction,
                        buffer.Length,
                        RetailFrameCodec.ToHex(
                            buffer,
                            Math.Max(WorldProxyRuntimeConstants.DefaultDumpBytes, _options.FirstPacketDumpBytes)));

                    if (RetailFrameCodec.TryDecodeRetailWorldFrame(buffer, out uint retailBodyLength, out uint retailOpcode))
                    {
                        _logger.LogInformation(
                            "[WorldProxy][POSTAUTH-DECODE] ConnectionId={ConnectionId}, Direction={Direction}, RetailBodyLength={RetailBodyLength}, RetailOpcode=0x{RetailOpcode:X8}",
                            connectionId,
                            direction,
                            retailBodyLength,
                            retailOpcode);
                    }
                }

                AuthBridgeHandlingResult authBridgeResult = await TryHandleAuthBridgeAsync(
                        connectionId,
                        direction,
                        buffer,
                        writer,
                        bridgeState,
                        firstAcoreChallengeBridged,
                        firstRetailAuthSessionBridged,
                        cancellationToken)
                    .ConfigureAwait(false);

                firstAcoreChallengeBridged = authBridgeResult.FirstAcoreChallengeBridged;
                firstRetailAuthSessionBridged = authBridgeResult.FirstRetailAuthSessionBridged;
                bool handledByBridge = authBridgeResult.HandledByBridge;
                totalBytes += authBridgeResult.BytesWritten;
                if (authBridgeResult.ShouldTerminateConnection)
                {
                    reader.AdvanceTo(buffer.End);
                    return totalBytes;
                }

                if (!handledByBridge)
                {
                    if (direction == "client->world" && retailPostAuthClientTranslator is not null)
                    {
                        if (!retailPostAuthClientTranslator.TryTransform(
                                buffer,
                                writer,
                                onDroppedOpcode: (opcode, payloadBytes) =>
                                {
                                    _logger.LogInformation(
                                        "[WorldProxy][MAP] Unmapped Retail opcode dropped. ConnectionId={ConnectionId}, Opcode=0x{Opcode:X8}, PayloadBytes={PayloadBytes}",
                                        connectionId,
                                        opcode,
                                        payloadBytes);
                                },
                                out long transformedBytes,
                                out string? transformError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][MAP] Failed to translate Retail post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                transformError ?? "<unknown>");

                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        totalBytes += transformedBytes;
                    }
                    else if (direction == "world->client" && acorePostAuthServerTranslator is not null)
                    {
                        if (!acorePostAuthServerTranslator.TryTransform(buffer, writer, out long transformedBytes, out string? transformError))
                        {
                            _logger.LogWarning(
                                "[WorldProxy][MAP] Failed to translate AC post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                                connectionId,
                                transformError ?? "<unknown>");

                            reader.AdvanceTo(buffer.End);
                            return totalBytes;
                        }

                        totalBytes += transformedBytes;
                    }
                    else
                    {
                        foreach (ReadOnlyMemory<byte> segment in buffer)
                        {
                            writer.Write(segment.Span);
                            totalBytes += segment.Length;
                        }
                    }
                }

                FlushResult flushResult = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                if (flushResult.IsCanceled || flushResult.IsCompleted)
                {
                    reader.AdvanceTo(buffer.End);
                    break;
                }

                if (direction == "client->world" && bridgeState.ConsumeClientRequestedDisconnect())
                {
                    _logger.LogInformation(
                        "[WorldProxy][MAP] Client requested world disconnect. ConnectionId={ConnectionId}, Direction={Direction}. Ending relay side.",
                        connectionId,
                        direction);
                    reader.AdvanceTo(buffer.End);
                    break;
                }

                AckGateDeferredFlushResult ackGateResult = await TryHandleAckGateAndDeferredFlushAsync(
                        connectionId,
                        direction,
                        writer,
                        bridgeState,
                        cancellationToken)
                    .ConfigureAwait(false);
                totalBytes += ackGateResult.BytesWritten;
                if (ackGateResult.ShouldTerminateConnection)
                {
                    reader.AdvanceTo(buffer.End);
                    return totalBytes;
                }

                if (ackGateResult.ShouldBreakRelay)
                {
                    reader.AdvanceTo(buffer.End);
                    break;
                }
            }

            reader.AdvanceTo(buffer.End);

            if (readResult.IsCanceled || readResult.IsCompleted)
            {
                break;
            }
        }

        return totalBytes;
    }

}
