using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async Task HandleConnectionAsync(TcpClient downstreamClient, uint connectionId, CancellationToken serverToken)
    {
        using (downstreamClient)
        {
            string downstreamRemote = downstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            string downstreamKey = WorldProxyRuntimeHelpers.ResolveDownstreamKey(downstreamClient.Client.RemoteEndPoint, downstreamRemote);
            downstreamClient.NoDelay = true;
            DateTimeOffset connectionOpenedAt = DateTimeOffset.UtcNow;

            _logger.LogInformation(
                "World connection opened: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}",
                connectionId,
                downstreamRemote);

            if (ReconnectCooldownHelpers.TryGetRemainingMs(
                    _reconnectCooldownUntilByKey,
                    _options.ReconnectCooldownMs,
                    downstreamKey,
                    out int reconnectCooldownRemainingMs))
            {
                _logger.LogInformation(
                    "[WorldProxy][ANTISPAM] Reconnect blocked by cooldown. ConnectionId={ConnectionId}, DownstreamKey={DownstreamKey}, RemainingMs={RemainingMs}, CooldownMs={CooldownMs}",
                    connectionId,
                    downstreamKey,
                    reconnectCooldownRemainingMs,
                    _options.ReconnectCooldownMs);
                return;
            }

            using var upstreamClient = new TcpClient(AddressFamily.InterNetwork);
            upstreamClient.NoDelay = true;

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                connectCts.CancelAfter(_options.UpstreamConnectTimeoutMs);
                await upstreamClient.ConnectAsync(_options.UpstreamAddress, _options.UpstreamPort, connectCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException)
            {
                _logger.LogWarning(
                    ex,
                    "Upstream connect failed: ConnectionId={ConnectionId}, Upstream={UpstreamAddress}:{UpstreamPort}",
                    connectionId,
                    _options.UpstreamAddress,
                    _options.UpstreamPort);
                return;
            }

            string upstreamRemote = upstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            _logger.LogInformation(
                "World upstream connected: ConnectionId={ConnectionId}, Upstream={UpstreamRemote}",
                connectionId,
                upstreamRemote);

            await using NetworkStream downstreamStream = downstreamClient.GetStream();
            await using NetworkStream upstreamStream = upstreamClient.GetStream();

            if (_options.EnableRetailConnectionInitializer)
            {
                bool initialized = await TryPerformRetailConnectionInitializerAsync(connectionId, downstreamStream, relayToken: serverToken).ConfigureAwait(false);
                if (!initialized)
                {
                    _logger.LogWarning(
                        "World initializer failed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}. Closing connection.",
                        connectionId,
                        downstreamRemote);
                    return;
                }
            }

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
            var bridgeState = new WorldProxyBridgeState(
                logger: _logger,
                retailWorldPacketCryptServerInitialCounter: (ulong)_options.RetailWorldPacketCryptServerInitialCounter,
                retailWorldPacketCryptUseSizeAsAad: _options.RetailWorldPacketCryptUseSizeAsAad,
                retailWorldPacketCryptAadSizeBytes: _options.RetailWorldPacketCryptAadSizeBytes,
                retailWorldPacketCryptUseEmptyAad: _options.RetailWorldPacketCryptUseEmptyAad,
                retailWorldPacketCryptNonceLayout: _options.RetailWorldPacketCryptNonceLayout,
                retailWorldPacketCryptServerNonceMagic: _options.RetailWorldPacketCryptServerNonceMagic,
                retailWorldPacketCryptClientNonceMagic: _options.RetailWorldPacketCryptClientNonceMagic);
            bridgeState.SetConnectionOpenedAt(connectionOpenedAt);
            bridgeState.SetBaseline(
                new HandshakeBaseline(
                    ScenarioId: _protocolOptions.ScenarioId,
                    ClientBuild: _protocolOptions.ClientBuild,
                    RealmConfig: _protocolOptions.RealmConfig,
                    AccountIdentity: _protocolOptions.AccountIdentity,
                    AckPolicy: _protocolOptions.AckPolicy,
                    PassThreshold: _protocolOptions.PassThreshold,
                    DeterministicReplayEnabled: _protocolOptions.DeterministicReplayEnabled,
                    FailureClassTarget: _protocolOptions.FailureClassTarget,
                    ActiveLayer: _protocolOptions.ActiveLayer,
                    ParityAxis: _protocolOptions.ParityAxis,
                    BaselineTimestampUtc: DateTimeOffset.UtcNow.ToString("O")));

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

            _logger.LogInformation(
                "World connection closed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}, BytesClientToWorld={BytesClientToWorld}, BytesWorldToClient={BytesWorldToClient}",
                connectionId,
                downstreamRemote,
                upstreamRemote,
                transferredClientToWorld,
                transferredWorldToClient);

            if (_options.EnableHandshakeLabReport)
            {
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
    }
}
