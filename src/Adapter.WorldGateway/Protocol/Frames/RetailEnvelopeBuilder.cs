using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class RetailEnvelopeBuilder
{
    public static byte[] BuildRetailWorldFrame(uint opcode, ReadOnlySpan<byte> payload)
    {
        uint bodyLength = checked((uint)(payload.Length + 4)); // opcode included
        byte[] frame = GC.AllocateUninitializedArray<byte>(16 + (int)bodyLength);
        Span<byte> span = frame;

        BinaryPrimitives.WriteUInt32LittleEndian(span[..4], bodyLength);
        span.Slice(4, 12).Clear(); // zeroed transport tag in non-encrypted world mode
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(16, 4), opcode);
        payload.CopyTo(span.Slice(20, payload.Length));
        return frame;
    }

    public static bool TryValidateRetailWorldEnvelope(ReadOnlySpan<byte> frame, out string actual)
    {
        actual = string.Empty;

        if (frame.Length < 20)
        {
            actual = $"frame_too_short={frame.Length}";
            return false;
        }

        uint size = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(0, 4));
        if (size < 4)
        {
            actual = $"invalid_size={size}";
            return false;
        }

        int expectedFrameBytes = checked((int)size + 16);
        uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(16, 4));
        int payloadBytes = checked((int)size - 4);

        actual =
            $"size={size};opcode=0x{opcode:X8};payload_bytes={payloadBytes};frame_bytes={frame.Length};expected_frame_bytes={expectedFrameBytes};tag_bytes=12";
        return frame.Length == expectedFrameBytes;
    }
}
