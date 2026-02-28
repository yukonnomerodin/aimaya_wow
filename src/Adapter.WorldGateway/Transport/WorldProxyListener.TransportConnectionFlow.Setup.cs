using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private bool TryPrepareDownstreamConnection(
        TcpClient downstreamClient,
        uint connectionId,
        out string downstreamRemote,
        out string downstreamKey,
        out DateTimeOffset connectionOpenedAt)
    {
        downstreamRemote = downstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
        downstreamKey = WorldProxyRuntimeHelpers.ResolveDownstreamKey(downstreamClient.Client.RemoteEndPoint, downstreamRemote);
        downstreamClient.NoDelay = true;
        connectionOpenedAt = DateTimeOffset.UtcNow;

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
            return false;
        }

        return true;
    }

    private async ValueTask<(bool Connected, string UpstreamRemote)> TryConnectUpstreamAsync(
        uint connectionId,
        TcpClient upstreamClient,
        CancellationToken serverToken)
    {
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
            return (false, "unknown");
        }

        string upstreamRemote = upstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _logger.LogInformation(
            "World upstream connected: ConnectionId={ConnectionId}, Upstream={UpstreamRemote}",
            connectionId,
            upstreamRemote);

        return (true, upstreamRemote);
    }

    private async ValueTask<bool> TryRunRetailConnectionInitializerAsync(
        uint connectionId,
        NetworkStream downstreamStream,
        string downstreamRemote,
        CancellationToken serverToken)
    {
        if (!_options.EnableRetailConnectionInitializer)
        {
            return true;
        }

        bool initialized = await TryPerformRetailConnectionInitializerAsync(connectionId, downstreamStream, relayToken: serverToken).ConfigureAwait(false);
        if (initialized)
        {
            return true;
        }

        _logger.LogWarning(
            "World initializer failed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}. Closing connection.",
            connectionId,
            downstreamRemote);
        return false;
    }

    private WorldProxyBridgeState CreateBridgeState(DateTimeOffset connectionOpenedAt)
    {
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
        return bridgeState;
    }
}
