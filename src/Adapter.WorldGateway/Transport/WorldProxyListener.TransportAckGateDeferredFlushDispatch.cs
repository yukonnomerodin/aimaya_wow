using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<AckGateDeferredFlushResult> DispatchAckGateDeferredFlushAsync(
        uint connectionId,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        AckGateDeferredPayload deferredPayload,
        CancellationToken cancellationToken)
    {
        DeferredBootstrapFlushResult deferredFlushResult = await TryFlushDeferredBootstrapPayloadAsync(
                connectionId,
                writer,
                bridgeState,
                deferredPayload.Payload,
                deferredPayload.StagedOpcodes,
                cancellationToken)
            .ConfigureAwait(false);

        long bytesWritten = deferredFlushResult.BytesWritten;
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
}
