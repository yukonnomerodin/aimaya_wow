using System.Buffers;
using System.IO.Pipelines;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private DeferredBootstrapFlushResult FlushSuppressedDeferredBootstrapPayload(
        uint connectionId,
        WorldProxyBridgeState bridgeState,
        byte[] deferredPayload,
        string stagedOpcodes)
    {
        bridgeState.MarkDeferredFlushPath("suppressed");
        bridgeState.MarkTemporalInvariant(
            name: "bootstrap_suppressed_for_probe",
            passed: false,
            expected: "bootstrap should flush in milestone scenario",
            actual: "bootstrap suppressed by probe mode");
        _logger.LogWarning(
            "[WorldProxy][HANDSHAKE] Probe mode: suppressed deferred post-auth bootstrap after ACK gate. ConnectionId={ConnectionId}, SuppressedBytes={Bytes}, Retail={Retail}",
            connectionId,
            deferredPayload.Length,
            stagedOpcodes);
        bridgeState.TryTransitionStage(
            BridgeStage.BOOTSTRAP_FLUSHED,
            "Deferred post-auth bootstrap suppressed by probe mode after ACK gate.");

        TryMarkExplicitBootstrapFlushMarker(
            connectionId,
            bridgeState,
            path: "suppressed",
            deferredPayload.Length,
            stagedOpcodes);

        return new DeferredBootstrapFlushResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: 0);
    }

    private async ValueTask<DeferredBootstrapFlushResult> FlushDeferredBootstrapRawPayloadFallbackAsync(
        uint connectionId,
        PipeWriter writer,
        WorldProxyBridgeState bridgeState,
        byte[] deferredPayload,
        string stagedOpcodes,
        string? splitError,
        CancellationToken cancellationToken)
    {
        long bytesWritten = 0;

        bridgeState.MarkDeferredFlushPath("raw_payload_fallback");
        _logger.LogWarning(
            "[WorldProxy][HANDSHAKE] Failed to split deferred post-auth bootstrap into Retail frames. ConnectionId={ConnectionId}, Error={Error}, Bytes={Bytes}, Retail={Retail}",
            connectionId,
            splitError ?? "<unknown>",
            deferredPayload.Length,
            stagedOpcodes);

        writer.Write(deferredPayload);
        bytesWritten += deferredPayload.Length;

        FlushResult deferredFlush = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (deferredFlush.IsCanceled || deferredFlush.IsCompleted)
        {
            return new DeferredBootstrapFlushResult(
                ShouldTerminateConnection: false,
                ShouldBreakRelay: true,
                BytesWritten: bytesWritten);
        }

        bridgeState.TryTransitionStage(
            BridgeStage.BOOTSTRAP_FLUSHED,
            "Deferred post-auth bootstrap flushed after ACK gate (raw payload fallback).");

        TryMarkExplicitBootstrapFlushMarker(
            connectionId,
            bridgeState,
            path: "raw_payload_fallback",
            deferredPayload.Length,
            stagedOpcodes);

        return new DeferredBootstrapFlushResult(
            ShouldTerminateConnection: false,
            ShouldBreakRelay: false,
            BytesWritten: bytesWritten);
    }

    private void TryMarkExplicitBootstrapFlushMarker(
        uint connectionId,
        WorldProxyBridgeState bridgeState,
        string path,
        int payloadBytes,
        string stagedOpcodes)
    {
        if (!_options.ProbeExplicitBootstrapFlushMarker)
        {
            return;
        }

        bridgeState.MarkTemporalInvariant(
            name: "bootstrap_flush_marker_explicit",
            passed: true,
            expected: "explicit marker emitted when deferred bootstrap flush path is reached",
            actual: $"path={path};bytes={payloadBytes};retail={stagedOpcodes}");
        _logger.LogInformation(
            "[WorldProxy][HANDSHAKE] Explicit bootstrap flush marker emitted. ConnectionId={ConnectionId}, Path={Path}, Bytes={Bytes}, Retail={Retail}",
            connectionId,
            path,
            payloadBytes,
            stagedOpcodes);
    }
}
