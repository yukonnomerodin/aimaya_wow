namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private static ProxyLoopReadResultProcessingResult CreateReadResultTerminateResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: true,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);

    private static ProxyLoopReadResultProcessingResult CreateReadResultBreakRelayResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: true,
            BytesWritten: bytesWritten);

    private static ProxyLoopReadResultProcessingResult CreateReadResultContinueResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
}
