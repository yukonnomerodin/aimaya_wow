using System.Buffers;

namespace Adapter.WorldGateway;

internal static class PostAuthClientFrameForwardingHelpers
{
    public static bool TryWriteEncryptedAcoreClientFrame(
        AuthCrypt authCrypt,
        uint opcode,
        ReadOnlySpan<byte> payload,
        IBufferWriter<byte> output,
        out long bytesWritten)
    {
        byte[] mapped = AcoreFrameBuilder.BuildAcoreClientFrame(opcode, payload);
        authCrypt.TransformClientToServer(mapped.AsSpan(0, 6));
        output.Write(mapped);
        bytesWritten = mapped.Length;
        return true;
    }
}
