using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class AcoreAuthChallengeDumpDecoder
{
    public static bool TryDecode(ReadOnlySequence<byte> buffer, out AcoreAuthChallengeDump dump)
    {
        dump = default;
        // AC world challenge packet: 2-byte size + 2-byte opcode + 40-byte payload.
        if (buffer.Length < 44)
        {
            return false;
        }

        Span<byte> frame = stackalloc byte[44];
        buffer.Slice(0, 44).CopyTo(frame);

        uint dosChallenge = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(4, 4));
        uint authSeed = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(8, 4));
        byte[] newSeed = GC.AllocateUninitializedArray<byte>(32);
        frame.Slice(12, 32).CopyTo(newSeed);
        string newSeedHex = Convert.ToHexString(newSeed);

        dump = new AcoreAuthChallengeDump(dosChallenge, authSeed, newSeedHex, newSeed);
        return true;
    }
}
