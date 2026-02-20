using System.Buffers;

namespace Adapter.AuthGateway;

internal ref struct ProtobufWriter
{
    private readonly IBufferWriter<byte> _writer;

    public ProtobufWriter(IBufferWriter<byte> writer)
    {
        _writer = writer;
    }

    public void WriteVarint(ulong value)
    {
        Span<byte> span = _writer.GetSpan(10);
        int index = 0;

        while (value >= 0x80)
        {
            span[index++] = (byte)((value & 0x7FUL) | 0x80UL);
            value >>= 7;
        }

        span[index++] = (byte)value;
        _writer.Advance(index);
    }

    public void WriteTag(int fieldNumber, int wireType)
    {
        if (fieldNumber <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(fieldNumber));
        }

        if ((uint)wireType > 5U)
        {
            throw new ArgumentOutOfRangeException(nameof(wireType));
        }

        ulong tag = ((ulong)fieldNumber << 3) | (uint)wireType;
        WriteVarint(tag);
    }

    public void WriteLengthPrefixedBytes(ReadOnlySpan<byte> data)
    {
        WriteVarint((ulong)data.Length);
        WriteBytes(data);
    }

    public void WriteBytes(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return;
        }

        Span<byte> destination = _writer.GetSpan(data.Length);
        data.CopyTo(destination);
        _writer.Advance(data.Length);
    }

    public void WriteFixed32(uint value)
    {
        Span<byte> destination = _writer.GetSpan(sizeof(uint));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination, value);
        _writer.Advance(sizeof(uint));
    }

    public void WriteFixed64(ulong value)
    {
        Span<byte> destination = _writer.GetSpan(sizeof(ulong));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
        _writer.Advance(sizeof(ulong));
    }

    public static int GetVarintLength(ulong value)
    {
        int length = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            length++;
        }

        return length;
    }
}

internal static class BnetResponseHeaderBuilder
{
    private const uint ResponseServiceId = 254;

    public static void WritePayloadResponseHeader(IBufferWriter<byte> writer, uint token, int payloadSize)
    {
        if (payloadSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadSize));
        }

        var protobuf = new ProtobufWriter(writer);

        protobuf.WriteTag(fieldNumber: 1, wireType: 0);
        protobuf.WriteVarint(ResponseServiceId);

        protobuf.WriteTag(fieldNumber: 3, wireType: 0);
        protobuf.WriteVarint(token);

        protobuf.WriteTag(fieldNumber: 5, wireType: 0);
        protobuf.WriteVarint((ulong)payloadSize);
    }

    public static void WriteStatusResponseHeader(IBufferWriter<byte> writer, uint token, uint status)
    {
        var protobuf = new ProtobufWriter(writer);

        protobuf.WriteTag(fieldNumber: 1, wireType: 0);
        protobuf.WriteVarint(ResponseServiceId);

        protobuf.WriteTag(fieldNumber: 3, wireType: 0);
        protobuf.WriteVarint(token);

        protobuf.WriteTag(fieldNumber: 6, wireType: 0);
        protobuf.WriteVarint(status);
    }
}

internal static class BnetRequestHeaderBuilder
{
    public static void WriteRequestHeader(
        IBufferWriter<byte> writer,
        uint serviceHash,
        uint methodId,
        uint token,
        int payloadSize)
    {
        if (payloadSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadSize));
        }

        var protobuf = new ProtobufWriter(writer);

        // bgs.protocol.Header.service_id = 0 (bindless request envelope)
        protobuf.WriteTag(fieldNumber: 1, wireType: 0);
        protobuf.WriteVarint(0);

        // method_id
        protobuf.WriteTag(fieldNumber: 2, wireType: 0);
        protobuf.WriteVarint(methodId);

        // token
        protobuf.WriteTag(fieldNumber: 3, wireType: 0);
        protobuf.WriteVarint(token);

        // payload size
        protobuf.WriteTag(fieldNumber: 5, wireType: 0);
        protobuf.WriteVarint((ulong)payloadSize);

        // service_hash (fixed32)
        protobuf.WriteTag(fieldNumber: 11, wireType: 5);
        protobuf.WriteFixed32(serviceHash);
    }
}
