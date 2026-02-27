using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class RetailCompressedPacketWrapper
{
    public static bool TryBuildRetailCompressedPacketFrame(
        ReadOnlySpan<byte> plainFrame,
        bool forceCompressionEnvelope,
        bool useRawDeflate,
        bool useStatefulRawDeflateSyncFlush,
        int rawDeflateLevel,
        bool checksumPayloadOnly,
        uint checksumSeed,
        bool compressedChecksumIncludeMetadata,
        StatefulRawDeflateSyncFlushCompressor? statefulCompressor,
        uint compressedPacketOpcode,
        int compressionThresholdBytes,
        out byte[] compressedFrame,
        out string? error)
    {
        compressedFrame = Array.Empty<byte>();
        error = null;

        if (plainFrame.Length < WorldGatewayProtocolConstants.RetailWorldFrameMinBytes)
        {
            error = $"Retail frame too short for compression wrapper: {plainFrame.Length} bytes.";
            return false;
        }

        uint bodyLength = BinaryPrimitives.ReadUInt32LittleEndian(plainFrame.Slice(0, WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
        if (bodyLength < WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
        {
            error = $"Retail frame has invalid body length for compression wrapper: {bodyLength}.";
            return false;
        }

        int expectedFrameBytes = checked((int)bodyLength + WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes);
        if (plainFrame.Length != expectedFrameBytes)
        {
            error = $"Retail frame size mismatch for compression wrapper: expected {expectedFrameBytes}, got {plainFrame.Length}.";
            return false;
        }

        uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(
            plainFrame.Slice(
                WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes,
                WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
        if (opcode == compressedPacketOpcode)
        {
            compressedFrame = plainFrame.ToArray();
            return true;
        }

        int payloadBytes = checked((int)bodyLength - WorldGatewayProtocolConstants.RetailWorldOpcodeBytes);
        if (!forceCompressionEnvelope && payloadBytes <= compressionThresholdBytes)
        {
            compressedFrame = plainFrame.ToArray();
            return true;
        }

        ReadOnlySpan<byte> uncompressed = plainFrame.Slice(WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes, checked((int)bodyLength));
        if (!RetailCompressionCodec.TryCompress(
                uncompressed,
                useRawDeflate,
                useStatefulRawDeflateSyncFlush,
                rawDeflateLevel,
                statefulCompressor,
                out byte[] compressedPayload,
                out string? compressionError))
        {
            error = compressionError ?? "Zlib compression failed.";
            return false;
        }

        const int CompressedPacketMetadataBytes = 12;
        byte[] payload = GC.AllocateUninitializedArray<byte>(CompressedPacketMetadataBytes + compressedPayload.Length);
        Span<byte> payloadSpan = payload;
        BinaryPrimitives.WriteUInt32LittleEndian(payloadSpan.Slice(0, 4), (uint)uncompressed.Length);
        ReadOnlySpan<byte> uncompressedChecksumSpan = checksumPayloadOnly && uncompressed.Length > 4
            ? uncompressed.Slice(WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
            : uncompressed;
        uint uncompressedChecksum = RetailCompressionCodec.ComputeAdler32(checksumSeed, uncompressedChecksumSpan);
        BinaryPrimitives.WriteUInt32LittleEndian(payloadSpan.Slice(4, 4), uncompressedChecksum);

        uint compressedChecksum;
        if (compressedChecksumIncludeMetadata)
        {
            byte[] checksumInput = GC.AllocateUninitializedArray<byte>(8 + compressedPayload.Length);
            Span<byte> checksumSpan = checksumInput;
            BinaryPrimitives.WriteUInt32LittleEndian(checksumSpan.Slice(0, 4), (uint)uncompressed.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(checksumSpan.Slice(4, 4), uncompressedChecksum);
            compressedPayload.CopyTo(checksumSpan.Slice(8));
            compressedChecksum = RetailCompressionCodec.ComputeAdler32(checksumSeed, checksumSpan);
        }
        else
        {
            compressedChecksum = RetailCompressionCodec.ComputeAdler32(checksumSeed, compressedPayload);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(payloadSpan.Slice(8, 4), compressedChecksum);
        compressedPayload.CopyTo(payloadSpan.Slice(CompressedPacketMetadataBytes));

        compressedFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(compressedPacketOpcode, payloadSpan);
        return true;
    }
}
