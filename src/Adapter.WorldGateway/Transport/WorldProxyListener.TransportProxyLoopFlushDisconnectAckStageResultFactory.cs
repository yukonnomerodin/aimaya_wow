namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private static ProxyBufferFlushDisconnectAckStageResult CreateFlushDisconnectAckTerminateResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: true,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);

    private static ProxyBufferFlushDisconnectAckStageResult CreateFlushDisconnectAckBreakRelayResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: true,
            BytesWritten: bytesWritten);

    private static ProxyBufferFlushDisconnectAckStageResult CreateFlushDisconnectAckContinueResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
}
