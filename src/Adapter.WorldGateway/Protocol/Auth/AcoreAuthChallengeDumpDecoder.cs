using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class AcoreAuthChallengeDumpDecoder
{
    public static bool TryDecode(ReadOnlySequence<byte> buffer, out AcoreAuthChallengeDump dump)
    {
        dump = default;
        // AC world challenge packet: 2-byte size + 2-byte opcode + 40-byte payload.
        if (buffer.Length < WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes)
        {
            return false;
        }

        Span<byte> frame = stackalloc byte[WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes];
        buffer.Slice(0, WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes).CopyTo(frame);

        uint dosChallenge = BinaryPrimitives.ReadUInt32LittleEndian(
            frame.Slice(WorldGatewayProtocolConstants.AcoreAuthChallengeDosChallengeOffsetBytes, sizeof(uint)));
        uint authSeed = BinaryPrimitives.ReadUInt32LittleEndian(
            frame.Slice(WorldGatewayProtocolConstants.AcoreAuthChallengeAuthSeedOffsetBytes, sizeof(uint)));
        byte[] newSeed = GC.AllocateUninitializedArray<byte>(WorldGatewayProtocolConstants.AcoreAuthChallengeNewSeedBytes);
        frame.Slice(
                WorldGatewayProtocolConstants.AcoreAuthChallengeNewSeedOffsetBytes,
                WorldGatewayProtocolConstants.AcoreAuthChallengeNewSeedBytes)
            .CopyTo(newSeed);
        string newSeedHex = Convert.ToHexString(newSeed);

        dump = new AcoreAuthChallengeDump(dosChallenge, authSeed, newSeedHex, newSeed);
        return true;
    }
}
