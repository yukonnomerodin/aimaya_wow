using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class RetailEnvelopeBuilder
{
    public static byte[] BuildRetailWorldFrame(uint opcode, ReadOnlySpan<byte> payload)
    {
        uint bodyLength = checked((uint)(payload.Length + WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)); // opcode included
        byte[] frame = GC.AllocateUninitializedArray<byte>(WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes + (int)bodyLength);
        Span<byte> span = frame;

        BinaryPrimitives.WriteUInt32LittleEndian(span[..WorldGatewayProtocolConstants.RetailWorldOpcodeBytes], bodyLength);
        span.Slice(WorldGatewayProtocolConstants.RetailWorldOpcodeBytes, WorldGatewayProtocolConstants.RetailWorldFrameTagBytes)
            .Clear(); // zeroed transport tag in non-encrypted world mode
        BinaryPrimitives.WriteUInt32LittleEndian(
            span.Slice(
                WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes,
                WorldGatewayProtocolConstants.RetailWorldOpcodeBytes),
            opcode);
        payload.CopyTo(span.Slice(WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes, payload.Length));
        return frame;
    }

    public static bool TryValidateRetailWorldEnvelope(ReadOnlySpan<byte> frame, out string actual)
    {
        actual = string.Empty;

        if (frame.Length < WorldGatewayProtocolConstants.RetailWorldFrameMinBytes)
        {
            actual = $"frame_too_short={frame.Length}";
            return false;
        }

        uint size = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(0, WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
        if (size < WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
        {
            actual = $"invalid_size={size}";
            return false;
        }

        int expectedFrameBytes = checked((int)size + WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes);
        uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes, WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
        int payloadBytes = checked((int)size - WorldGatewayProtocolConstants.RetailWorldOpcodeBytes);

        actual =
            $"size={size};opcode=0x{opcode:X8};payload_bytes={payloadBytes};frame_bytes={frame.Length};expected_frame_bytes={expectedFrameBytes};tag_bytes={WorldGatewayProtocolConstants.RetailWorldFrameTagBytes}";
        return frame.Length == expectedFrameBytes;
    }
}
