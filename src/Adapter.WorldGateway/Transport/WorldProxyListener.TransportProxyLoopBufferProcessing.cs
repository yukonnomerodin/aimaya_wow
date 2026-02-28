using System.Buffers;
using System.IO.Pipelines;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProxyLoopBufferProcessingResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private sealed class TransportProxyLoopState
    {
        public bool FirstChunkDumped { get; set; }
        public bool FirstAcoreChallengeBridged { get; set; }
        public bool FirstRetailAuthSessionBridged { get; set; }
        public bool FirstPostAuthDumpedClient { get; set; }
        public bool FirstPostAuthDumpedServer { get; set; }
        public int AcoreServerFramesLogged { get; set; }
        public RetailPostAuthClientTranslator? RetailPostAuthClientTranslator { get; set; }
        public AcorePostAuthServerTranslator? AcorePostAuthServerTranslator { get; set; }
    }

    private async ValueTask<ProxyLoopBufferProcessingResult> TryProcessProxyBufferAsync(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        bool waitForEnterEncryptedAckGate,
        TransportProxyLoopState loopState,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;
        if (_options.EnableFirstPacketDump && !loopState.FirstChunkDumped)
        {
            loopState.FirstChunkDumped = true;
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

        loopState.RetailPostAuthClientTranslator = EnsureRetailPostAuthClientTranslator(
            direction,
            loopState.RetailPostAuthClientTranslator,
            bridgeState,
            connectionId,
            downstreamKey);

        loopState.AcorePostAuthServerTranslator = EnsureAcorePostAuthServerTranslator(
            direction,
            loopState.AcorePostAuthServerTranslator,
            bridgeState,
            connectionId,
            waitForEnterEncryptedAckGate,
            onFrameDecoded: (opcode, payloadBytes) =>
            {
                // Limit frame spam while collecting first handshake map.
                if (loopState.AcoreServerFramesLogged < 32)
                {
                    loopState.AcoreServerFramesLogged++;
                    _logger.LogInformation(
                        "[WorldProxy][AC->CLIENT FRAME] ConnectionId={ConnectionId}, Opcode=0x{Opcode:X4}, PayloadBytes={PayloadBytes}",
                        connectionId,
                        opcode,
                        payloadBytes);
                }
            });

        if (direction == "world->client" &&
            !loopState.FirstPostAuthDumpedServer &&
            bridgeState.TryGetAcoreHeaderCrypt(out _))
        {
            loopState.FirstPostAuthDumpedServer = true;
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
            !loopState.FirstPostAuthDumpedClient &&
            bridgeState.TryGetAcoreHeaderCrypt(out _))
        {
            loopState.FirstPostAuthDumpedClient = true;
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
                loopState.FirstAcoreChallengeBridged,
                loopState.FirstRetailAuthSessionBridged,
                cancellationToken)
            .ConfigureAwait(false);

        loopState.FirstAcoreChallengeBridged = authBridgeResult.FirstAcoreChallengeBridged;
        loopState.FirstRetailAuthSessionBridged = authBridgeResult.FirstRetailAuthSessionBridged;
        bytesWritten += authBridgeResult.BytesWritten;
        if (authBridgeResult.ShouldTerminateConnection)
        {
            return new ProxyLoopBufferProcessingResult(
                ShouldTerminateConnection: true,
                ShouldBreakRelay: false,
                BytesWritten: bytesWritten);
        }

        if (!authBridgeResult.HandledByBridge)
        {
            if (direction == "client->world" && loopState.RetailPostAuthClientTranslator is not null)
            {
                if (!loopState.RetailPostAuthClientTranslator.TryTransform(
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

                    return new ProxyLoopBufferProcessingResult(
                        ShouldTerminateConnection: true,
                        ShouldBreakRelay: false,
                        BytesWritten: bytesWritten);
                }

                bytesWritten += transformedBytes;
            }
            else if (direction == "world->client" && loopState.AcorePostAuthServerTranslator is not null)
            {
                if (!loopState.AcorePostAuthServerTranslator.TryTransform(buffer, writer, out long transformedBytes, out string? transformError))
                {
                    _logger.LogWarning(
                        "[WorldProxy][MAP] Failed to translate AC post-auth packet. ConnectionId={ConnectionId}, Error={Error}",
                        connectionId,
                        transformError ?? "<unknown>");

                    return new ProxyLoopBufferProcessingResult(
                        ShouldTerminateConnection: true,
                        ShouldBreakRelay: false,
                        BytesWritten: bytesWritten);
                }

                bytesWritten += transformedBytes;
            }
            else
            {
                foreach (ReadOnlyMemory<byte> segment in buffer)
                {
                    writer.Write(segment.Span);
                    bytesWritten += segment.Length;
                }
            }
        }

        FlushResult flushResult = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (flushResult.IsCanceled || flushResult.IsCompleted)
        {
            return new ProxyLoopBufferProcessingResult(
                ShouldTerminateConnection: false,
                ShouldBreakRelay: true,
                BytesWritten: bytesWritten);
        }

        if (direction == "client->world" && bridgeState.ConsumeClientRequestedDisconnect())
        {
            _logger.LogInformation(
                "[WorldProxy][MAP] Client requested world disconnect. ConnectionId={ConnectionId}, Direction={Direction}. Ending relay side.",
                connectionId,
                direction);
            return new ProxyLoopBufferProcessingResult(
                ShouldTerminateConnection: false,
                ShouldBreakRelay: true,
                BytesWritten: bytesWritten);
        }

        AckGateDeferredFlushResult ackGateResult = await TryHandleAckGateAndDeferredFlushAsync(
                connectionId,
                direction,
                writer,
                bridgeState,
                cancellationToken)
            .ConfigureAwait(false);
        bytesWritten += ackGateResult.BytesWritten;
        if (ackGateResult.ShouldTerminateConnection)
        {
            return new ProxyLoopBufferProcessingResult(
                ShouldTerminateConnection: true,
                ShouldBreakRelay: false,
                BytesWritten: bytesWritten);
        }

        if (ackGateResult.ShouldBreakRelay)
        {
            return new ProxyLoopBufferProcessingResult(
                ShouldTerminateConnection: false,
                ShouldBreakRelay: true,
                BytesWritten: bytesWritten);
        }

        return new ProxyLoopBufferProcessingResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }
}
