using System.IO.Pipelines;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProxyBufferFlushDisconnectAckStageResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private async ValueTask<ProxyBufferFlushDisconnectAckStageResult> TryRunProxyBufferFlushDisconnectAckStageAsync(
        uint connectionId,
        string direction,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;
        FlushResult flushResult = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (flushResult.IsCanceled || flushResult.IsCompleted)
        {
            return new ProxyBufferFlushDisconnectAckStageResult(
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
            return new ProxyBufferFlushDisconnectAckStageResult(
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
            return new ProxyBufferFlushDisconnectAckStageResult(
                ShouldTerminateConnection: true,
                ShouldBreakRelay: false,
                BytesWritten: bytesWritten);
        }

        if (ackGateResult.ShouldBreakRelay)
        {
            return new ProxyBufferFlushDisconnectAckStageResult(
                ShouldTerminateConnection: false,
                ShouldBreakRelay: true,
                BytesWritten: bytesWritten);
        }

        return new ProxyBufferFlushDisconnectAckStageResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }
}
