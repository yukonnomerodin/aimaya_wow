using System.Buffers;
using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct AuthBridgeHandlingResult(
        bool HandledByBridge,
        bool FirstAcoreChallengeBridged,
        bool FirstRetailAuthSessionBridged,
        long BytesWritten,
        bool ShouldTerminateConnection);

    private async ValueTask<AuthBridgeHandlingResult> TryHandleAuthBridgeAsync(
        uint connectionId,
        string direction,
        ReadOnlySequence<byte> buffer,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        bool firstAcoreChallengeBridged,
        bool firstRetailAuthSessionBridged,
        CancellationToken cancellationToken)
    {
        AuthBridgeHandlingResult? acoreToRetail = TryHandleAcoreToRetailAuthChallengeBridge(
            connectionId,
            direction,
            buffer,
            writer,
            bridgeState,
            firstAcoreChallengeBridged,
            firstRetailAuthSessionBridged);
        if (acoreToRetail.HasValue)
        {
            return acoreToRetail.Value;
        }

        AuthBridgeHandlingResult? retailToAcore = await TryHandleRetailToAcoreAuthSessionBridgeAsync(
                connectionId,
                direction,
                buffer,
                writer,
                bridgeState,
                firstAcoreChallengeBridged,
                firstRetailAuthSessionBridged,
                cancellationToken)
            .ConfigureAwait(false);
        if (retailToAcore.HasValue)
        {
            return retailToAcore.Value;
        }

        return new AuthBridgeHandlingResult(
            HandledByBridge: false,
            FirstAcoreChallengeBridged: firstAcoreChallengeBridged,
            FirstRetailAuthSessionBridged: firstRetailAuthSessionBridged,
            BytesWritten: 0,
            ShouldTerminateConnection: false);
    }
}
