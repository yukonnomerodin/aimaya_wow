using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal sealed class BitPackedBufferWriter
{
    private byte[] _buffer;
    private int _position;
    private int _bitPos = 8;
    private byte _curBitValue;

    public BitPackedBufferWriter(int initialCapacity = 64)
    {
        _buffer = GC.AllocateUninitializedArray<byte>(Math.Max(32, initialCapacity));
    }

    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _position);

    public void WriteByte(byte value)
    {
        EnsureByteAligned();
        EnsureCapacity(1);
        _buffer[_position++] = value;
    }

    public void WriteAscii(string value)
    {
        EnsureByteAligned();
        int len = value.Length;
        EnsureCapacity(len);
        for (int i = 0; i < len; i++)
        {
            _buffer[_position++] = (byte)value[i];
        }
    }

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        EnsureByteAligned();
        EnsureCapacity(value.Length);
        value.CopyTo(_buffer.AsSpan(_position, value.Length));
        _position += value.Length;
    }

    public void WriteUInt32LE(uint value)
    {
        EnsureByteAligned();
        EnsureCapacity(4);
        BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_position, 4), value);
        _position += 4;
    }

    public void WriteUInt64LE(ulong value)
    {
        EnsureByteAligned();
        EnsureCapacity(8);
        BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_position, 8), value);
        _position += 8;
    }

    public void WriteInt32LE(int value)
    {
        EnsureByteAligned();
        EnsureCapacity(4);
        BinaryPrimitives.WriteInt32LittleEndian(_buffer.AsSpan(_position, 4), value);
        _position += 4;
    }

    public void WriteInt16LE(short value)
    {
        EnsureByteAligned();
        EnsureCapacity(2);
        BinaryPrimitives.WriteInt16LittleEndian(_buffer.AsSpan(_position, 2), value);
        _position += 2;
    }

    public void WriteInt64LE(long value)
    {
        EnsureByteAligned();
        EnsureCapacity(8);
        BinaryPrimitives.WriteInt64LittleEndian(_buffer.AsSpan(_position, 8), value);
        _position += 8;
    }

    public void WriteBit(bool bit)
    {
        _bitPos--;
        if (bit)
        {
            _curBitValue |= (byte)(1 << _bitPos);
        }

        if (_bitPos == 0)
        {
            EnsureCapacity(1);
            _buffer[_position++] = _curBitValue;
            _curBitValue = 0;
            _bitPos = 8;
        }
    }

    public void WriteBits(ulong value, int bits)
    {
        if (bits <= 0)
        {
            return;
        }

        // Canonical MSB-first write, one bit at a time.
        for (int i = bits - 1; i >= 0; i--)
        {
            WriteBit(((value >> i) & 1UL) != 0);
        }
    }

    public void FlushBits()
    {
        if (_bitPos == 8)
        {
            return;
        }

        EnsureCapacity(1);
        _buffer[_position++] = _curBitValue;
        _curBitValue = 0;
        _bitPos = 8;
    }

    private void EnsureByteAligned()
    {
        FlushBits();
    }

    private void EnsureCapacity(int additionalBytes)
    {
        int required = _position + additionalBytes;
        if (required <= _buffer.Length)
        {
            return;
        }

        int newSize = _buffer.Length * 2;
        while (newSize < required)
        {
            newSize *= 2;
        }

        byte[] resized = GC.AllocateUninitializedArray<byte>(newSize);
        _buffer.AsSpan(0, _position).CopyTo(resized);
        _buffer = resized;
    }
}
