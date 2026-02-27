using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class AcoreFrameBuilder
{
    public static byte[] BuildAcoreClientFrame(uint opcode, ReadOnlySpan<byte> payload)
    {
        ushort size = checked((ushort)(payload.Length + 4)); // opcode included
        byte[] frame = GC.AllocateUninitializedArray<byte>(2 + 4 + payload.Length);
        Span<byte> span = frame;

        BinaryPrimitives.WriteUInt16BigEndian(span[..2], size);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(2, 4), opcode);
        payload.CopyTo(span.Slice(6, payload.Length));

        return frame;
    }
}
