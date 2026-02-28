namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProxyLoopBufferProcessingResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private readonly record struct ProxyLoopReadResultProcessingResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);

    private readonly record struct ProxyBufferAuthBridgeAndTransformStageResult(
        bool ShouldTerminateConnection,
        long BytesWritten);

    private readonly record struct ProxyBufferFlushDisconnectAckStageResult(
        bool ShouldTerminateConnection,
        bool ShouldBreakRelay,
        long BytesWritten);
}
