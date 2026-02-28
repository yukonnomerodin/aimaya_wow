using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct RelayFailureRecoveryOutcome(
        long ClientToWorldBytes,
        long WorldToClientBytes,
        bool DrainAttempted,
        bool DrainCompleted,
        long DrainElapsedMs,
        string Details);

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
            RelayFailureRecoveryOutcome recoveryOutcome = await ApplyRelayFailureRecoveryPolicyAsync(
                    downstreamToUpstream,
                    upstreamToDownstream,
                    relayCts)
                .ConfigureAwait(false);
            transferredClientToWorld = recoveryOutcome.ClientToWorldBytes;
            transferredWorldToClient = recoveryOutcome.WorldToClientBytes;
            bridgeState.SetEvidenceContext("Transport", "relay failure recovery policy");
            bridgeState.MarkTemporalInvariant(
                name: "relay_failure_recovery_policy_applied",
                passed: true,
                expected: "relay faults apply configured recovery policy before connection shutdown",
                actual: $"policy={_relayFailureRecoveryPolicy};drain_attempted={recoveryOutcome.DrainAttempted};drain_completed={recoveryOutcome.DrainCompleted};drain_elapsed_ms={recoveryOutcome.DrainElapsedMs};details={recoveryOutcome.Details}");

            string clientToWorldStatus = downstreamToUpstream.Status.ToString();
            string worldToClientStatus = upstreamToDownstream.Status.ToString();
            string clientToWorldError = downstreamToUpstream.Exception?.GetBaseException().Message ?? "<none>";
            string worldToClientError = upstreamToDownstream.Exception?.GetBaseException().Message ?? "<none>";
            _logger.LogWarning(
                ex,
                "Proxy loop error: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}, ClientToWorldStatus={ClientToWorldStatus}, WorldToClientStatus={WorldToClientStatus}, ClientToWorldError={ClientToWorldError}, WorldToClientError={WorldToClientError}, RelayFailureRecoveryPolicy={RelayFailureRecoveryPolicy}, RelayFailureRecoveryDetails={RelayFailureRecoveryDetails}",
                connectionId,
                downstreamRemote,
                upstreamRemote,
                clientToWorldStatus,
                worldToClientStatus,
                clientToWorldError,
                worldToClientError,
                _relayFailureRecoveryPolicy,
                recoveryOutcome.Details);
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

    private async ValueTask<RelayFailureRecoveryOutcome> ApplyRelayFailureRecoveryPolicyAsync(
        Task<long> downstreamToUpstream,
        Task<long> upstreamToDownstream,
        CancellationTokenSource relayCts)
    {
        relayCts.Cancel();

        long clientToWorld = 0;
        long worldToClient = 0;
        bool drainAttempted = false;
        bool drainCompleted = false;
        long drainElapsedMs = 0;

        if (_relayFailureRecoveryPolicy == RelayFailureRecoveryPolicy.CancelSiblingDrainAndClose &&
            _options.RelayFailureDrainTimeoutMs > 0)
        {
            drainAttempted = true;
            long drainStartMs = Environment.TickCount64;
            Task allRelays = Task.WhenAll(downstreamToUpstream, upstreamToDownstream);
            Task completed = await Task.WhenAny(
                    allRelays,
                    Task.Delay(_options.RelayFailureDrainTimeoutMs))
                .ConfigureAwait(false);
            drainElapsedMs = Math.Max(0, Environment.TickCount64 - drainStartMs);
            drainCompleted = ReferenceEquals(completed, allRelays);
        }

        if (downstreamToUpstream.IsCompletedSuccessfully)
        {
            clientToWorld = downstreamToUpstream.Result;
        }

        if (upstreamToDownstream.IsCompletedSuccessfully)
        {
            worldToClient = upstreamToDownstream.Result;
        }

        string details = drainAttempted
            ? $"drain_timeout_ms={_options.RelayFailureDrainTimeoutMs}"
            : "drain_disabled";
        return new RelayFailureRecoveryOutcome(
            ClientToWorldBytes: clientToWorld,
            WorldToClientBytes: worldToClient,
            DrainAttempted: drainAttempted,
            DrainCompleted: drainCompleted,
            DrainElapsedMs: drainElapsedMs,
            Details: details);
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
            HandshakeLabReportWriteRequest request = new(
                ConnectionId: connectionId,
                Report: report,
                RunlogsDirectory: WorldGatewayPathResolver.EnsureHandshakeRunlogsDirectory(_options),
                ProofPackRoot: WorldGatewayPathResolver.ResolveProofPackRoot(_options));

            bool queued =
                _handshakeDiagnosticsDispatchMode == HandshakeDiagnosticsDispatchMode.BackgroundChannel &&
                TryEnqueueHandshakeLabReport(request);
            if (!queued)
            {
                WriteHandshakeLabReportCore(request);
            }
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
