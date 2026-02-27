using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Adapter.WorldGateway;

internal static class RetailAuthChallengeBuilder
{
    public static bool TryBuildFromAcore(
        ReadOnlySequence<byte> buffer,
        bool randomizeDosBlock,
        out byte[] retailFrame,
        out int consumedBytes,
        out RetailAuthChallengeProof proof)
    {
        retailFrame = Array.Empty<byte>();
        consumedBytes = 0;
        proof = default;

        if (buffer.Length < 44)
        {
            return false;
        }

        Span<byte> acFrame = stackalloc byte[44];
        buffer.Slice(0, 44).CopyTo(acFrame);

        ushort sizeBE = BinaryPrimitives.ReadUInt16BigEndian(acFrame[..2]);
        ushort opcodeLE = BinaryPrimitives.ReadUInt16LittleEndian(acFrame.Slice(2, 2));
        if (sizeBE != 42 || opcodeLE != WorldGatewayOpcodes.AcoreSmsgAuthChallenge)
        {
            return false;
        }

        Span<byte> acPayload = acFrame.Slice(4, 40);
        Span<byte> retailPayload = stackalloc byte[65];
        uint dosChallenge = BinaryPrimitives.ReadUInt32LittleEndian(acPayload[..4]);
        uint authSeed = BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(4, 4));
        ReadOnlySpan<byte> acChallengeSeed = acPayload.Slice(8, 32);
        Span<byte> dosBlock = retailPayload.Slice(0, 32);
        Span<byte> challengeBlock = retailPayload.Slice(32, 32);
        string dosBlockSource;

        // Retail/TC auth challenge layout:
        // 32 bytes DosChallenge + 32 bytes Challenge + 1 byte DosZeroBits.
        // Optional TC-like mode: dos-challenge block is independent random bytes.
        if (randomizeDosBlock)
        {
            RandomNumberGenerator.Fill(dosBlock);
            dosBlockSource = "random32";
        }
        else
        {
            acChallengeSeed.CopyTo(dosBlock);
            dosBlockSource = "mirror_ac_newseed";
        }

        // Keep challenge block bound to AC new seed so downstream auth bridge remains stable.
        acChallengeSeed.CopyTo(challengeBlock);
        retailPayload[64] = 1;

        retailFrame = GC.AllocateUninitializedArray<byte>(16 + 4 + 65);
        Span<byte> frame = retailFrame;

        BinaryPrimitives.WriteUInt32LittleEndian(frame[..4], 69); // opcode (4) + payload (65)
        frame.Slice(4, 12).Clear(); // tag=0 before encrypted mode
        BinaryPrimitives.WriteUInt32LittleEndian(frame.Slice(16, 4), WorldGatewayOpcodes.RetailSmsgAuthChallenge);
        retailPayload.CopyTo(frame.Slice(20, 65));

        proof = new RetailAuthChallengeProof(
            TimestampUtc: DateTimeOffset.UtcNow.ToString("O"),
            RetailOpcode: WorldGatewayOpcodes.RetailSmsgAuthChallenge,
            AcoreDosChallenge: dosChallenge,
            AcoreAuthSeed: authSeed,
            AcoreNewSeedHex: Convert.ToHexString(acChallengeSeed),
            DosBlockSource: dosBlockSource,
            DosBlockHex: Convert.ToHexString(dosBlock),
            ChallengeBlockHex: Convert.ToHexString(challengeBlock),
            RetailPayloadHex: Convert.ToHexString(retailPayload),
            RetailPayloadBytes: retailPayload.Length);

        consumedBytes = 44;
        return true;
    }
}
