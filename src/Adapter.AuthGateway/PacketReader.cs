using System.Buffers.Binary;
using System.Text;

namespace Adapter.AuthGateway;

/// <summary>
/// Zero-allocation packet reader over ReadOnlySpan.
/// Supports byte-aligned primitives and bit-length-prefixed strings.
/// </summary>
public ref struct PacketReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _byteOffset;
    private int _bitOffset;

    public PacketReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _byteOffset = 0;
        _bitOffset = 0;
    }

    public int RemainingBytes
    {
        get
        {
            int remainingBits = RemainingBits;
            return remainingBits <= 0 ? 0 : remainingBits / 8;
        }
    }

    public int RemainingBits
    {
        get
        {
            int consumedBits = (_byteOffset * 8) + _bitOffset;
            int totalBits = _buffer.Length * 8;
            int remaining = totalBits - consumedBits;
            return remaining > 0 ? remaining : 0;
        }
    }

    public bool IsByteAligned => _bitOffset == 0;

    public bool TryAlignToByte()
    {
        if (_bitOffset == 0)
        {
            return true;
        }

        int nextByte = _byteOffset + 1;
        if (nextByte > _buffer.Length)
        {
            return false;
        }

        _byteOffset = nextByte;
        _bitOffset = 0;
        return true;
    }

    public bool TryReadByte(out byte value)
    {
        value = 0;
        if (!TryAlignToByte())
        {
            return false;
        }

        if (_byteOffset >= _buffer.Length)
        {
            return false;
        }

        value = _buffer[_byteOffset++];
        return true;
    }

    public bool TryReadUInt16LittleEndian(out ushort value)
    {
        value = 0;
        if (!TryAlignToByte() || RemainingBytes < sizeof(ushort))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Slice(_byteOffset, sizeof(ushort)));
        _byteOffset += sizeof(ushort);
        return true;
    }

    public bool TryReadUInt32LittleEndian(out uint value)
    {
        value = 0;
        if (!TryAlignToByte() || RemainingBytes < sizeof(uint))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_byteOffset, sizeof(uint)));
        _byteOffset += sizeof(uint);
        return true;
    }

    public bool TryReadBytes(Span<byte> destination)
    {
        if (!TryAlignToByte() || RemainingBytes < destination.Length)
        {
            return false;
        }

        _buffer.Slice(_byteOffset, destination.Length).CopyTo(destination);
        _byteOffset += destination.Length;
        return true;
    }

    public bool TryReadString(int byteLength, out string value)
    {
        value = string.Empty;
        if (byteLength < 0)
        {
            return false;
        }

        if (!TryAlignToByte() || RemainingBytes < byteLength)
        {
            return false;
        }

        value = Encoding.UTF8.GetString(_buffer.Slice(_byteOffset, byteLength));
        _byteOffset += byteLength;
        return true;
    }

    public bool TryReadBits(int bitCount, out uint value)
    {
        value = 0;
        if (bitCount <= 0 || bitCount > 32 || RemainingBits < bitCount)
        {
            return false;
        }

        // Retail packet bit reader compatibility:
        // read MSB-first within each source byte.
        for (int i = 0; i < bitCount; i++)
        {
            byte current = _buffer[_byteOffset];
            int bitIndex = 7 - _bitOffset;
            int bit = (current >> bitIndex) & 0x1;
            value = (value << 1) | (uint)bit;

            _bitOffset++;
            if (_bitOffset == 8)
            {
                _bitOffset = 0;
                _byteOffset++;
            }
        }

        return true;
    }

    public bool TryReadLengthPrefixedString(
        int lengthBitCount,
        int maxLength,
        out string value)
    {
        value = string.Empty;
        if (lengthBitCount <= 0 || maxLength <= 0)
        {
            return false;
        }

        if (!TryReadBits(lengthBitCount, out uint length))
        {
            return false;
        }

        if (length == 0 || length > maxLength)
        {
            return false;
        }

        return TryReadString((int)length, out value);
    }
}
