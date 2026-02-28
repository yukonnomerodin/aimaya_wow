using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<AckGateDeferredFlushResult> TryHandleAckGateWorldToClientAsync(
        uint connectionId,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        AckGateWaitAndFlushTriggerResult ackGateResult = ResolveAckGateWaitAndFlushTrigger(connectionId, bridgeState);
        if (ackGateResult.ShouldTerminateConnection)
        {
            return CreateAckGateTerminateResult(bytesWritten: 0);
        }

        bridgeState.MarkDeferredFlushPath(ackGateResult.DeferredFlushPath);
        return await TryHandleAckGateDeferredResultPathAsync(
                connectionId,
                writer,
                bridgeState,
                ackGateResult.ShouldFlushDeferredNow,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
