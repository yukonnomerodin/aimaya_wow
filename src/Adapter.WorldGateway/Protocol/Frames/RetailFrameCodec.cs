using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class RetailFrameCodec
{
    public static string ToHex(ReadOnlySequence<byte> buffer, int maxBytes)
    {
        int length = (int)Math.Min(buffer.Length, maxBytes);
        if (length <= 0)
        {
            return string.Empty;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> head = rented.AsSpan(0, length);
            buffer.Slice(0, length).CopyTo(head);
            return Convert.ToHexString(head);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public static bool TryDecodeFirstHeader(ReadOnlySequence<byte> buffer, out DumpHeaderDecode decode)
    {
        decode = default;
        if (buffer.Length < 4)
        {
            return false;
        }

        Span<byte> header = stackalloc byte[4];
        buffer.Slice(0, 4).CopyTo(header);

        ushort sizeBE = BinaryPrimitives.ReadUInt16BigEndian(header[..2]);
        ushort sizeLE = BinaryPrimitives.ReadUInt16LittleEndian(header[..2]);
        ushort opcodeBE = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(2, 2));
        ushort opcodeLE = BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(2, 2));

        bool sizeBEMatches = sizeBE + 2 == buffer.Length || sizeBE + 4 == buffer.Length;
        decode = new DumpHeaderDecode(sizeBE, sizeLE, opcodeLE, opcodeBE, sizeBEMatches);
        return true;
    }

    public static bool TryDecodeRetailWorldFrame(ReadOnlySequence<byte> buffer, out uint bodyLength, out uint opcode)
    {
        bodyLength = 0;
        opcode = 0;

        if (buffer.Length < 20)
        {
            return false;
        }

        Span<byte> header = stackalloc byte[20];
        buffer.Slice(0, 20).CopyTo(header);
        bodyLength = BinaryPrimitives.ReadUInt32LittleEndian(header[..4]);
        opcode = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(16, 4));
        return true;
    }

    public static bool TrySplitRetailWorldFrames(ReadOnlySpan<byte> payload, out List<RetailFrameChunk> frames, out string? error)
    {
        frames = new List<RetailFrameChunk>(8);
        error = null;

        const int retailHeaderBytes = 16;
        const int retailMinFrameBytes = 20;
        const int maxRetailFrameBytes = 16 * 1024 * 1024;

        int offset = 0;
        while (offset < payload.Length)
        {
            int remaining = payload.Length - offset;
            if (remaining < retailMinFrameBytes)
            {
                error = $"Retail frame split failed: remaining bytes {remaining} are less than minimum frame size {retailMinFrameBytes}.";
                return false;
            }

            ReadOnlySpan<byte> frameStart = payload.Slice(offset);
            uint bodyLength = BinaryPrimitives.ReadUInt32LittleEndian(frameStart[..4]);
            long frameBytesLong = retailHeaderBytes + (long)bodyLength;
            if (frameBytesLong < retailMinFrameBytes || frameBytesLong > maxRetailFrameBytes)
            {
                error = $"Retail frame split failed: invalid frame size {frameBytesLong} at offset {offset} (bodyLength={bodyLength}).";
                return false;
            }

            if (frameBytesLong > int.MaxValue)
            {
                error = $"Retail frame split failed: frame size {frameBytesLong} exceeds Int32 at offset {offset}.";
                return false;
            }

            int frameBytes = (int)frameBytesLong;
            if (frameBytes > remaining)
            {
                error = $"Retail frame split failed: truncated frame at offset {offset} (frameBytes={frameBytes}, remaining={remaining}).";
                return false;
            }

            uint opcode = bodyLength >= 4
                ? BinaryPrimitives.ReadUInt32LittleEndian(frameStart.Slice(16, 4))
                : 0;

            byte[] frame = GC.AllocateUninitializedArray<byte>(frameBytes);
            frameStart.Slice(0, frameBytes).CopyTo(frame);
            frames.Add(new RetailFrameChunk(frame, opcode, (int)bodyLength));

            offset += frameBytes;
        }

        return true;
    }
}
