using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<AckGateDeferredFlushResult> TryHandleAckGateDeferredResultPathAsync(
        uint connectionId,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        bool shouldFlushDeferredNow,
        CancellationToken cancellationToken)
    {
        if (!TryTakeAckGateDeferredPayload(
                bridgeState,
                shouldFlushDeferredNow,
                out AckGateDeferredPayload deferredPayload))
        {
            return CreateAckGateContinueResult(bytesWritten: 0);
        }

        return await DispatchAckGateDeferredFlushAsync(
                connectionId,
                writer,
                bridgeState,
                deferredPayload,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
