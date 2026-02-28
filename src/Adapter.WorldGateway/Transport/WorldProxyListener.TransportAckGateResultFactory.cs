namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
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
