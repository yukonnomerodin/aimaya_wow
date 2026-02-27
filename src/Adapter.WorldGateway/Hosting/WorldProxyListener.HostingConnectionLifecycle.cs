using System.Net.Sockets;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private async Task RunAcceptLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener!.AcceptTcpClientAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            uint connectionId = unchecked((uint)Interlocked.Increment(ref _connectionSequence));
            Task connectionTask = HandleConnectionAsync(client, connectionId, stoppingToken);
            TrackActiveConnection(connectionTask);
        }
    }

    private void TrackActiveConnection(Task connectionTask)
    {
        lock (_activeConnectionsLock)
        {
            _activeConnections.Add(connectionTask);
        }

        _ = connectionTask.ContinueWith(
            _ =>
            {
                lock (_activeConnectionsLock)
                {
                    _activeConnections.Remove(connectionTask);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private async Task StopListenerAndAwaitActiveConnectionsAsync()
    {
        _listener!.Stop();

        Task[] pending;
        lock (_activeConnectionsLock)
        {
            pending = _activeConnections.ToArray();
        }

        if (pending.Length > 0)
        {
            await Task.WhenAll(pending).ConfigureAwait(false);
        }
    }
}
