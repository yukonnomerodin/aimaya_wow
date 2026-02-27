using System.Buffers;

namespace Adapter.WorldGateway;

internal static class PostAuthServerFrameWriteHelpers
{
    public static bool TryWriteProtectedRetailServerFrame(
        WorldProxyBridgeState bridgeState,
        byte[] plainFrame,
        IBufferWriter<byte> output,
        out long bytesWritten,
        out string? error)
    {
        bytesWritten = 0;
        error = null;

        if (!bridgeState.TryProtectRetailServerFrame(plainFrame, out byte[] protectedFrame, out _, out string? protectError))
        {
            error = $"Failed to protect Retail server frame: {protectError ?? "<unknown>"}";
            return false;
        }

        output.Write(protectedFrame);
        bytesWritten = protectedFrame.Length;
        return true;
    }

    public static bool TryWriteProtectedRetailServerFrameBatch(
        WorldProxyBridgeState bridgeState,
        ReadOnlySpan<byte> payload,
        IBufferWriter<byte> output,
        out long bytesWritten,
        out string? error)
    {
        bytesWritten = 0;
        error = null;

        if (!RetailFrameCodec.TrySplitRetailWorldFrames(payload, out List<RetailFrameChunk> frames, out string? splitError))
        {
            error = splitError ?? "Failed to split retail frame batch.";
            return false;
        }

        for (int index = 0; index < frames.Count; index++)
        {
            RetailFrameChunk frame = frames[index];
            if (!TryWriteProtectedRetailServerFrame(bridgeState, frame.Frame, output, out long frameBytes, out error))
            {
                return false;
            }

            bytesWritten += frameBytes;
        }

        return true;
    }
}
