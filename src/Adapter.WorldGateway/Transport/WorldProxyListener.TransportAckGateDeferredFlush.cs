using System.IO.Pipelines;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct AckGateDeferredFlushResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private async ValueTask<AckGateDeferredFlushResult> TryHandleAckGateAndDeferredFlushAsync(
        uint connectionId,
        string direction,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;

        if (direction == "world->client" && bridgeState.IsAwaitingEnterEncryptedAck)
        {
            AckGateWaitAndFlushTriggerResult ackGateResult = ResolveAckGateWaitAndFlushTrigger(connectionId, bridgeState);
            if (ackGateResult.ShouldTerminateConnection)
            {
                return new AckGateDeferredFlushResult(ShouldTerminateConnection: true, ShouldBreakRelay: false, BytesWritten: bytesWritten);
            }

            bridgeState.MarkDeferredFlushPath(ackGateResult.DeferredFlushPath);
            if (ackGateResult.ShouldFlushDeferredNow &&
                bridgeState.TryTakeDeferredPostAuthPayload(out byte[] deferredPayload, out string stagedOpcodes) &&
                deferredPayload.Length > 0)
            {
                DeferredBootstrapFlushResult deferredFlushResult = await TryFlushDeferredBootstrapPayloadAsync(
                        connectionId,
                        writer,
                        bridgeState,
                        deferredPayload,
                        stagedOpcodes,
                        cancellationToken)
                    .ConfigureAwait(false);
                bytesWritten += deferredFlushResult.BytesWritten;
                if (deferredFlushResult.ShouldTerminateConnection)
                {
                    return new AckGateDeferredFlushResult(ShouldTerminateConnection: true, ShouldBreakRelay: false, BytesWritten: bytesWritten);
                }

                if (deferredFlushResult.ShouldBreakRelay)
                {
                    return new AckGateDeferredFlushResult(ShouldTerminateConnection: false, ShouldBreakRelay: true, BytesWritten: bytesWritten);
                }
            }
        }

        return new AckGateDeferredFlushResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }
}
