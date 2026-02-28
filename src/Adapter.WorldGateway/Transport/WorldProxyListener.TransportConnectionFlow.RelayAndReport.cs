using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<(long ClientToWorld, long WorldToClient)> RunRelayLoopAsync(
        uint connectionId,
        string downstreamRemote,
        string upstreamRemote,
        string downstreamKey,
        WorldProxyBridgeState bridgeState,
        NetworkStream downstreamStream,
        NetworkStream upstreamStream,
        CancellationToken serverToken)
    {
        var downstreamReader = PipeReader.Create(
            downstreamStream,
            new StreamPipeReaderOptions(
                bufferSize: _options.ReaderBufferSize,
                minimumReadSize: _options.MinimumReadSize,
                leaveOpen: true));

        var downstreamWriter = PipeWriter.Create(downstreamStream, new StreamPipeWriterOptions(leaveOpen: true));
        var upstreamReader = PipeReader.Create(
            upstreamStream,
            new StreamPipeReaderOptions(
                bufferSize: _options.ReaderBufferSize,
                minimumReadSize: _options.MinimumReadSize,
                leaveOpen: true));

        var upstreamWriter = PipeWriter.Create(upstreamStream, new StreamPipeWriterOptions(leaveOpen: true));

        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);

        Task<long> downstreamToUpstream = ProxyStreamAsync(
            connectionId,
            "client->world",
            downstreamReader,
            upstreamWriter,
            downstreamKey,
            bridgeState,
            relayCts.Token);

        Task<long> upstreamToDownstream = ProxyStreamAsync(
            connectionId,
            "world->client",
            upstreamReader,
            downstreamWriter,
            downstreamKey,
            bridgeState,
            relayCts.Token);

        long transferredClientToWorld = 0;
        long transferredWorldToClient = 0;

        try
        {
            Task completed = await Task.WhenAny(downstreamToUpstream, upstreamToDownstream).ConfigureAwait(false);
            string firstCompletedDirection = ReferenceEquals(completed, downstreamToUpstream)
                ? "client->world"
                : "world->client";
            string firstCompletedStatus = completed.IsFaulted
                ? "faulted"
                : completed.IsCanceled
                    ? "canceled"
                    : "completed";
            string firstCompletedError = completed.Exception?.GetBaseException().Message ?? "<none>";
            _logger.LogInformation(
                "[WorldProxy][L4] First relay side finished. ConnectionId={ConnectionId}, Direction={Direction}, Status={Status}, Error={Error}",
                connectionId,
                firstCompletedDirection,
                firstCompletedStatus,
                firstCompletedError);
            relayCts.Cancel();

            try
            {
                await completed.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when one side closes first.
            }

            try
            {
                transferredClientToWorld = await downstreamToUpstream.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Ignore cancellation, this is normal on half-close.
            }

            try
            {
                transferredWorldToClient = await upstreamToDownstream.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Ignore cancellation, this is normal on half-close.
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Proxy loop error: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}",
                connectionId,
                downstreamRemote,
                upstreamRemote);
        }
        finally
        {
            await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(downstreamReader).ConfigureAwait(false);
            await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(downstreamWriter).ConfigureAwait(false);
            await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(upstreamReader).ConfigureAwait(false);
            await WorldProxyRuntimeHelpers.CompletePipeSafelyAsync(upstreamWriter).ConfigureAwait(false);
        }

        return (transferredClientToWorld, transferredWorldToClient);
    }

    private void TryWriteHandshakeLabReport(
        uint connectionId,
        WorldProxyBridgeState bridgeState,
        DateTimeOffset connectionOpenedAt,
        long transferredClientToWorld,
        long transferredWorldToClient)
    {
        if (!_options.EnableHandshakeLabReport)
        {
            return;
        }

        try
        {
            HandshakeLabReport report = HandshakeLabReport.Create(
                connectionId,
                _options,
                _protocolOptions,
                bridgeState,
                connectionOpenedAt,
                DateTimeOffset.UtcNow,
                transferredClientToWorld,
                transferredWorldToClient);

            string reportPath = HandshakeDiagnosticsWriters.WriteHandshakeLabReport(
                report,
                WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options));
            HandshakeDiagnosticsWriters.AppendNegativeEvidenceMatrixRow(
                reportPath,
                report,
                WorldGatewayPathResolver.ResolveProofPackRoot(_options));
            _logger.LogInformation(
                "[WorldProxy][HANDSHAKE-LAB] Report written. ConnectionId={ConnectionId}, Path={Path}",
                connectionId,
                reportPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][HANDSHAKE-LAB] Failed to write report. ConnectionId={ConnectionId}",
                connectionId);
        }
    }
}
