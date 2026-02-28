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

    private static AckGateDeferredFlushResult CreateAckGateTerminateResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: true,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);

    private static AckGateDeferredFlushResult CreateAckGateBreakRelayResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: true,
            BytesWritten: bytesWritten);

    private static AckGateDeferredFlushResult CreateAckGateContinueResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
}
