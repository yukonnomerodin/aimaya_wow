using System.Buffers;
using System.IO.Pipelines;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProxyBufferAuthBridgeAndTransformStageResult(
        bool ShouldTerminateConnection,
        long BytesWritten);

    private async ValueTask<ProxyBufferAuthBridgeAndTransformStageResult> TryRunProxyBufferAuthBridgeAndTransformStageAsync(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        TransportProxyLoopState loopState,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;
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
            return CreateAuthBridgeTransformTerminateResult(bytesWritten);
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

                    return CreateAuthBridgeTransformTerminateResult(bytesWritten);
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

                    return CreateAuthBridgeTransformTerminateResult(bytesWritten);
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

        return CreateAuthBridgeTransformContinueResult(bytesWritten);
    }
}
