using System;
using System.Buffers;
using System.IO;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async ValueTask<bool> TryPerformRetailConnectionInitializerAsync(
        uint connectionId,
        NetworkStream downstreamStream,
        CancellationToken relayToken)
    {
        using var initCts = CancellationTokenSource.CreateLinkedTokenSource(relayToken);
        initCts.CancelAfter(_options.InitializerTimeoutMs);

        try
        {
            await downstreamStream.WriteAsync(ServerConnectionInitializer, initCts.Token).ConfigureAwait(false);
            await downstreamStream.FlushAsync(initCts.Token).ConfigureAwait(false);

            byte[] rented = ArrayPool<byte>.Shared.Rent(ClientConnectionInitializer.Length);
            try
            {
                Memory<byte> clientInit = rented.AsMemory(0, ClientConnectionInitializer.Length);
                bool ok = await WorldProxyRuntimeHelpers.TryReadExactAsync(downstreamStream, clientInit, initCts.Token).ConfigureAwait(false);
                if (!ok)
                {
                    _logger.LogWarning(
                        "[WorldProxy][INIT] Failed to read client initializer. ConnectionId={ConnectionId}, ExpectedBytes={ExpectedBytes}",
                        connectionId,
                        ClientConnectionInitializer.Length);
                    return false;
                }

                ReadOnlySpan<byte> expected = ClientConnectionInitializer;
                if (!clientInit.Span.SequenceEqual(expected))
                {
                    _logger.LogWarning(
                        "[WorldProxy][INIT] Invalid client initializer. ConnectionId={ConnectionId}, Expected=\"{Expected}\", ActualHex={ActualHex}",
                        connectionId,
                        Encoding.ASCII.GetString(ClientConnectionInitializer),
                        Convert.ToHexString(clientInit.Span));
                    return false;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }

            _logger.LogInformation(
                "[WorldProxy][INIT] Retail world initializer completed. ConnectionId={ConnectionId}",
                connectionId);
            return true;
        }
        catch (OperationCanceledException) when (initCts.IsCancellationRequested)
        {
            _logger.LogWarning(
                "[WorldProxy][INIT] Retail world initializer timeout. ConnectionId={ConnectionId}, TimeoutMs={TimeoutMs}",
                connectionId,
                _options.InitializerTimeoutMs);
            return false;
        }
        catch (IOException ex)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][INIT] IO error during retail initializer. ConnectionId={ConnectionId}",
                connectionId);
            return false;
        }
        catch (SocketException ex)
        {
            _logger.LogWarning(
                ex,
                "[WorldProxy][INIT] Socket error during retail initializer. ConnectionId={ConnectionId}",
                connectionId);
            return false;
        }
    }
}
