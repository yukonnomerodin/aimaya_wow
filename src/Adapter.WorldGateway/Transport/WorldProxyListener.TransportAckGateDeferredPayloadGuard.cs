namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct AckGateDeferredPayload(
        byte[] Payload,
        string StagedOpcodes);

    private static bool TryTakeAckGateDeferredPayload(
        WorldProxyBridgeState bridgeState,
        bool shouldFlushDeferredNow,
        out AckGateDeferredPayload deferredPayload)
    {
        deferredPayload = default;
        if (!shouldFlushDeferredNow ||
            !bridgeState.TryTakeDeferredPostAuthPayload(out byte[] payload, out string stagedOpcodes) ||
            payload.Length == 0)
        {
            return false;
        }

        deferredPayload = new AckGateDeferredPayload(
            Payload: payload,
            StagedOpcodes: stagedOpcodes);
        return true;
    }
}
