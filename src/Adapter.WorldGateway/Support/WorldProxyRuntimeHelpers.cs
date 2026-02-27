using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;

namespace Adapter.WorldGateway;

internal static class WorldProxyRuntimeHelpers
{
    public static string ResolveDownstreamKey(EndPoint? remoteEndPoint, string fallbackRemote)
    {
        if (remoteEndPoint is IPEndPoint ipEndpoint)
        {
            return ipEndpoint.Address.ToString();
        }

        return string.IsNullOrWhiteSpace(fallbackRemote) ? "unknown" : fallbackRemote;
    }

    public static async ValueTask<bool> TryReadExactAsync(
        NetworkStream stream,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int read = await stream.ReadAsync(destination[offset..], cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    public static async ValueTask CompletePipeSafelyAsync(PipeReader reader)
    {
        try
        {
            await reader.CompleteAsync().ConfigureAwait(false);
        }
        catch
        {
            // Ignore complete errors during teardown.
        }
    }

    public static async ValueTask CompletePipeSafelyAsync(PipeWriter writer)
    {
        try
        {
            await writer.CompleteAsync().ConfigureAwait(false);
        }
        catch
        {
            // Ignore complete errors during teardown.
        }
    }
}
