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

        if (buffer.Length < WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes)
        {
            return false;
        }

        Span<byte> acFrame = stackalloc byte[WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes];
        buffer.Slice(0, WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes).CopyTo(acFrame);

        ushort sizeBE = BinaryPrimitives.ReadUInt16BigEndian(acFrame[..sizeof(ushort)]);
        ushort opcodeLE = BinaryPrimitives.ReadUInt16LittleEndian(acFrame.Slice(sizeof(ushort), sizeof(ushort)));
        if (sizeBE != WorldGatewayProtocolConstants.AcoreAuthChallengePacketSizeFieldValue ||
            opcodeLE != WorldGatewayOpcodes.AcoreSmsgAuthChallenge)
        {
            return false;
        }

        Span<byte> acPayload = acFrame.Slice(
            WorldGatewayProtocolConstants.AcoreAuthChallengePayloadOffsetBytes,
            WorldGatewayProtocolConstants.AcoreAuthChallengePayloadBytes);
        Span<byte> retailPayload = stackalloc byte[WorldGatewayProtocolConstants.RetailAuthChallengePayloadBytes];
        uint dosChallenge = BinaryPrimitives.ReadUInt32LittleEndian(acPayload[..sizeof(uint)]);
        uint authSeed = BinaryPrimitives.ReadUInt32LittleEndian(acPayload.Slice(sizeof(uint), sizeof(uint)));
        ReadOnlySpan<byte> acChallengeSeed = acPayload.Slice(
            sizeof(uint) * 2,
            WorldGatewayProtocolConstants.AcoreAuthChallengeNewSeedBytes);
        Span<byte> dosBlock = retailPayload.Slice(0, WorldGatewayProtocolConstants.RetailAuthChallengeDosBlockBytes);
        Span<byte> challengeBlock = retailPayload.Slice(
            WorldGatewayProtocolConstants.RetailAuthChallengePayloadChallengeBlockOffsetBytes,
            WorldGatewayProtocolConstants.RetailAuthChallengeChallengeBlockBytes);
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
        retailPayload[WorldGatewayProtocolConstants.RetailAuthChallengePayloadTrailingFlagOffsetBytes] = 1;

        retailFrame = GC.AllocateUninitializedArray<byte>(
            WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes +
            WorldGatewayProtocolConstants.RetailAuthChallengeBodyBytes);
        Span<byte> frame = retailFrame;

        BinaryPrimitives.WriteUInt32LittleEndian(
            frame[..WorldGatewayProtocolConstants.RetailWorldOpcodeBytes],
            (uint)WorldGatewayProtocolConstants.RetailAuthChallengeBodyBytes); // opcode + payload
        frame.Slice(
                WorldGatewayProtocolConstants.RetailWorldOpcodeBytes,
                WorldGatewayProtocolConstants.RetailWorldFrameTagBytes)
            .Clear(); // tag=0 before encrypted mode
        BinaryPrimitives.WriteUInt32LittleEndian(
            frame.Slice(
                WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes,
                WorldGatewayProtocolConstants.RetailWorldOpcodeBytes),
            WorldGatewayOpcodes.RetailSmsgAuthChallenge);
        retailPayload.CopyTo(
            frame.Slice(
                WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes,
                WorldGatewayProtocolConstants.RetailAuthChallengePayloadBytes));

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

        consumedBytes = WorldGatewayProtocolConstants.AcoreAuthChallengeFrameBytes;
        return true;
    }
}
