namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private static ProxyBufferAuthBridgeAndTransformStageResult CreateAuthBridgeTransformTerminateResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: true,
            BytesWritten: bytesWritten);

    private static ProxyBufferAuthBridgeAndTransformStageResult CreateAuthBridgeTransformContinueResult(long bytesWritten) =>
        new(
            ShouldTerminateConnection: false,
            BytesWritten: bytesWritten);
}
