using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct DeferredBootstrapFlushResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private async ValueTask<DeferredBootstrapFlushResult> TryFlushDeferredBootstrapPayloadAsync(
        uint connectionId,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        byte[] deferredPayload,
        string stagedOpcodes,
        CancellationToken cancellationToken)
    {
        if (_options.SuppressPostAuthBootstrapForProbe && !_options.ProbeBareAuthResponseOnly)
        {
            return FlushSuppressedDeferredBootstrapPayload(
                connectionId,
                bridgeState,
                deferredPayload,
                stagedOpcodes);
        }

        if (!RetailFrameCodec.TrySplitRetailWorldFrames(deferredPayload, out List<RetailFrameChunk> deferredFrames, out string? splitError))
        {
            return await FlushDeferredBootstrapRawPayloadFallbackAsync(
                    connectionId,
                    writer,
                    bridgeState,
                    deferredPayload,
                    stagedOpcodes,
                    splitError,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return await FlushDeferredBootstrapProtectedFramesAsync(
                connectionId,
                writer,
                bridgeState,
                deferredFrames,
                deferredPayload,
                stagedOpcodes,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
