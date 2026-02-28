using System.Buffers;
using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProxyLoopReadResultProcessingResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private async ValueTask<ProxyLoopReadResultProcessingResult> TryHandleProxyLoopReadResultLifecycleAsync(
        uint connectionId,
        string direction,
        PipeReader reader,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        bool waitForEnterEncryptedAckGate,
        TransportProxyLoopState loopState,
        ReadResult readResult,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;
        ReadOnlySequence<byte> buffer = readResult.Buffer;
        if (!buffer.IsEmpty)
        {
            ProxyLoopBufferProcessingResult processResult = await TryProcessProxyBufferAsync(
                    connectionId,
                    direction,
                    buffer,
                    writer,
                    downstreamKey,
                    bridgeState,
                    waitForEnterEncryptedAckGate,
                    loopState,
                    cancellationToken)
                .ConfigureAwait(false);
            bytesWritten += processResult.BytesWritten;
            if (processResult.ShouldTerminateConnection)
            {
                reader.AdvanceTo(buffer.End);
                return new ProxyLoopReadResultProcessingResult(
                    ShouldTerminateConnection: true,
                    ShouldBreakRelay: false,
                    BytesWritten: bytesWritten);
            }

            if (processResult.ShouldBreakRelay)
            {
                reader.AdvanceTo(buffer.End);
                return new ProxyLoopReadResultProcessingResult(
                    ShouldTerminateConnection: false,
                    ShouldBreakRelay: true,
                    BytesWritten: bytesWritten);
            }
        }

        reader.AdvanceTo(buffer.End);
        if (readResult.IsCanceled || readResult.IsCompleted)
        {
            return new ProxyLoopReadResultProcessingResult(
                ShouldTerminateConnection: false,
                ShouldBreakRelay: true,
                BytesWritten: bytesWritten);
        }

        return new ProxyLoopReadResultProcessingResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }
}
