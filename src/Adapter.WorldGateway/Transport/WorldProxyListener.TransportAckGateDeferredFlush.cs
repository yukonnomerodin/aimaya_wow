using System.IO.Pipelines;

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
        if (direction != "world->client" || !bridgeState.IsAwaitingEnterEncryptedAck)
        {
            return CreateAckGateContinueResult(bytesWritten: 0);
        }

        return await TryHandleAckGateWorldToClientAsync(
                connectionId,
                writer,
                bridgeState,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
