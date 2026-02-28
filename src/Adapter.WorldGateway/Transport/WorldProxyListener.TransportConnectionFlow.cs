using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async Task HandleConnectionAsync(TcpClient downstreamClient, uint connectionId, CancellationToken serverToken)
    {
        using (downstreamClient)
        {
            if (!TryPrepareDownstreamConnection(
                    downstreamClient,
                    connectionId,
                    out string downstreamRemote,
                    out string downstreamKey,
                    out DateTimeOffset connectionOpenedAt))
            {
                return;
            }

            using var upstreamClient = new TcpClient(AddressFamily.InterNetwork);
            upstreamClient.NoDelay = true;

            (bool connected, string upstreamRemote) = await TryConnectUpstreamAsync(
                    connectionId,
                    upstreamClient,
                    serverToken)
                .ConfigureAwait(false);
            if (!connected)
            {
                return;
            }

            await using NetworkStream downstreamStream = downstreamClient.GetStream();
            await using NetworkStream upstreamStream = upstreamClient.GetStream();

            if (!await TryRunRetailConnectionInitializerAsync(
                    connectionId,
                    downstreamStream,
                    downstreamRemote,
                    serverToken)
                .ConfigureAwait(false))
            {
                return;
            }

            WorldProxyBridgeState bridgeState = CreateBridgeState(connectionOpenedAt);
            (long transferredClientToWorld, long transferredWorldToClient) = await RunRelayLoopAsync(
                    connectionId,
                    downstreamRemote,
                    upstreamRemote,
                    downstreamKey,
                    bridgeState,
                    downstreamStream,
                    upstreamStream,
                    serverToken)
                .ConfigureAwait(false);

            _logger.LogInformation(
                "World connection closed: ConnectionId={ConnectionId}, Downstream={DownstreamRemote}, Upstream={UpstreamRemote}, BytesClientToWorld={BytesClientToWorld}, BytesWorldToClient={BytesWorldToClient}",
                connectionId,
                downstreamRemote,
                upstreamRemote,
                transferredClientToWorld,
                transferredWorldToClient);

            TryWriteHandshakeLabReport(
                connectionId,
                bridgeState,
                connectionOpenedAt,
                transferredClientToWorld,
                transferredWorldToClient);
        }
    }
}
