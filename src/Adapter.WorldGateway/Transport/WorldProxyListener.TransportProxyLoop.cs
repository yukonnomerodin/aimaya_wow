using System.IO.Pipelines;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async Task<long> ProxyStreamAsync(
        uint connectionId,
        string direction,
        PipeReader reader,
        PipeWriter writer,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        CancellationToken cancellationToken)
    {
        long totalBytes = 0;
        TransportProxyLoopState loopState = new();
        bool waitForEnterEncryptedAckGate = AckPolicyResolver.ResolveEffectiveWaitForAckGate(
            _ackPolicyMode,
            _options.EnterEncryptedModeAckGateEnabled,
            _protocolOptions.AckPolicy,
            _protocolOptions.AckPolicyDecisionPath,
            out _);

        while (!cancellationToken.IsCancellationRequested)
        {
            ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ProxyLoopReadResultProcessingResult lifecycleResult = await TryHandleProxyLoopReadResultLifecycleAsync(
                    connectionId,
                    direction,
                    reader,
                    writer,
                    downstreamKey,
                    bridgeState,
                    waitForEnterEncryptedAckGate,
                    loopState,
                    readResult,
                    cancellationToken)
                .ConfigureAwait(false);
            totalBytes += lifecycleResult.BytesWritten;
            if (lifecycleResult.ShouldTerminateConnection)
            {
                return totalBytes;
            }

            if (lifecycleResult.ShouldBreakRelay)
            {
                break;
            }
        }

        return totalBytes;
    }

}
