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
        RunProxyBufferPreparationStage(
            connectionId,
            direction,
            buffer,
            downstreamKey,
            bridgeState,
            waitForEnterEncryptedAckGate,
            loopState);

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
            return CreateBufferProcessingTerminateResult(bytesWritten);
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

                    return CreateBufferProcessingTerminateResult(bytesWritten);
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

                    return CreateBufferProcessingTerminateResult(bytesWritten);
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
            return CreateBufferProcessingBreakRelayResult(bytesWritten);
        }

        if (direction == "client->world" && bridgeState.ConsumeClientRequestedDisconnect())
        {
            _logger.LogInformation(
                "[WorldProxy][MAP] Client requested world disconnect. ConnectionId={ConnectionId}, Direction={Direction}. Ending relay side.",
                connectionId,
                direction);
            return CreateBufferProcessingBreakRelayResult(bytesWritten);
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
            return CreateBufferProcessingTerminateResult(bytesWritten);
        }

        if (ackGateResult.ShouldBreakRelay)
        {
            return CreateBufferProcessingBreakRelayResult(bytesWritten);
        }

        return CreateBufferProcessingContinueResult(bytesWritten);
    }
}
