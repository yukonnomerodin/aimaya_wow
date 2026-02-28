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
        long bytesWritten = 0;
        if (!TryTakeAckGateDeferredPayload(
                bridgeState,
                shouldFlushDeferredNow,
                out AckGateDeferredPayload deferredPayload))
        {
            return CreateAckGateContinueResult(bytesWritten);
        }

        DeferredBootstrapFlushResult deferredFlushResult = await TryFlushDeferredBootstrapPayloadAsync(
                connectionId,
                writer,
                bridgeState,
                deferredPayload.Payload,
                deferredPayload.StagedOpcodes,
                cancellationToken)
            .ConfigureAwait(false);
        bytesWritten += deferredFlushResult.BytesWritten;
        if (deferredFlushResult.ShouldTerminateConnection)
        {
            return CreateAckGateTerminateResult(bytesWritten);
        }

        if (deferredFlushResult.ShouldBreakRelay)
        {
            return CreateAckGateBreakRelayResult(bytesWritten);
        }

        return CreateAckGateContinueResult(bytesWritten);
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
