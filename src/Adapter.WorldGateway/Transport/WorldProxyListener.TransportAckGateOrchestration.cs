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
        return await TryHandleResolvedAckGateOrchestrationAsync(
                connectionId,
                writer,
                bridgeState,
                ackGateResult,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
