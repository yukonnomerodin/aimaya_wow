using System.Buffers;
using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProxyLoopBufferProcessingResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private sealed class TransportProxyLoopState
    {
        public bool FirstChunkDumped { get; set; }
        public bool FirstAcoreChallengeBridged { get; set; }
        public bool FirstRetailAuthSessionBridged { get; set; }
        public bool FirstPostAuthDumpedClient { get; set; }
        public bool FirstPostAuthDumpedServer { get; set; }
        public int AcoreServerFramesLogged { get; set; }
        public RetailPostAuthClientTranslator? RetailPostAuthClientTranslator { get; set; }
        public AcorePostAuthServerTranslator? AcorePostAuthServerTranslator { get; set; }
    }

    private async ValueTask<ProxyLoopBufferProcessingResult> TryProcessProxyBufferAsync(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        bool waitForEnterEncryptedAckGate,
        TransportProxyLoopState loopState,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;
        RunProxyBufferPreparationStage(
            connectionId,
            direction,
            buffer,
            downstreamKey,
            bridgeState,
            waitForEnterEncryptedAckGate,
            loopState);

        ProxyBufferAuthBridgeAndTransformStageResult authTransformResult = await TryRunProxyBufferAuthBridgeAndTransformStageAsync(
                connectionId,
                direction,
                buffer,
                writer,
                bridgeState,
                loopState,
                cancellationToken)
            .ConfigureAwait(false);
        bytesWritten += authTransformResult.BytesWritten;
        if (authTransformResult.ShouldTerminateConnection)
        {
            return CreateBufferProcessingTerminateResult(bytesWritten);
        }

        ProxyBufferFlushDisconnectAckStageResult flushDisconnectAckResult = await TryRunProxyBufferFlushDisconnectAckStageAsync(
                connectionId,
                direction,
                writer,
                bridgeState,
                cancellationToken)
            .ConfigureAwait(false);
        bytesWritten += flushDisconnectAckResult.BytesWritten;
        if (flushDisconnectAckResult.ShouldTerminateConnection)
        {
            return CreateBufferProcessingTerminateResult(bytesWritten);
        }

        if (flushDisconnectAckResult.ShouldBreakRelay)
        {
            return CreateBufferProcessingBreakRelayResult(bytesWritten);
        }

        return CreateBufferProcessingContinueResult(bytesWritten);
    }
}
