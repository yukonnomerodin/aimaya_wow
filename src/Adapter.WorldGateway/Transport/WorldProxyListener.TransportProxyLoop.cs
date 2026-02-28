using System.Buffers;
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
            ReadOnlySequence<byte> buffer = readResult.Buffer;

            if (!buffer.IsEmpty)
            {
                ProxyLoopBufferProcessingResult processResult = await TryProcessProxyBufferAsync(
                        connectionId,
                        direction,
                        buffer,
                        writer,
                        downstreamKey,
                        bridgeState,
                        waitForEnterEncryptedAckGate,
                        loopState,
                        cancellationToken)
                    .ConfigureAwait(false);
                totalBytes += processResult.BytesWritten;
                if (processResult.ShouldTerminateConnection)
                {
                    reader.AdvanceTo(buffer.End);
                    return totalBytes;
                }

                if (processResult.ShouldBreakRelay)
                {
                    reader.AdvanceTo(buffer.End);
                    break;
                }
            }

            reader.AdvanceTo(buffer.End);

            if (readResult.IsCanceled || readResult.IsCompleted)
            {
                break;
            }
        }

        return totalBytes;
    }

}
