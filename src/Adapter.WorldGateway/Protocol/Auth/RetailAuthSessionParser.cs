using System.Buffers;
using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class RetailAuthSessionParser
{
    public static bool TryParseRetailAuthSessionFrame(
        ReadOnlySequence<byte> buffer,
        uint authSessionOpcode,
        int retailAuthFixedPayloadBytes,
        out RetailAuthSessionFrame frame)
    {
        frame = default;

        if (buffer.Length < WorldGatewayProtocolConstants.RetailWorldFrameMinBytes)
        {
            return false;
        }

        Span<byte> header = stackalloc byte[WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes];
        buffer.Slice(0, WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes).CopyTo(header);

        uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(header[..WorldGatewayProtocolConstants.RetailWorldOpcodeBytes]);
        if (packetSize < WorldGatewayProtocolConstants.RetailWorldOpcodeBytes)
        {
            return false;
        }

        int fullFrameBytes = checked(WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes + (int)packetSize);
        if (buffer.Length < fullFrameBytes)
        {
            return false;
        }

        uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(
            header.Slice(
                WorldGatewayProtocolConstants.RetailWorldFrameOuterHeaderBytes,
                WorldGatewayProtocolConstants.RetailWorldOpcodeBytes));
        if (opcode != authSessionOpcode)
        {
            return false;
        }

        int payloadBytes = (int)packetSize - WorldGatewayProtocolConstants.RetailWorldOpcodeBytes;
        if (payloadBytes < retailAuthFixedPayloadBytes)
        {
            return false;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(payloadBytes);
        try
        {
            Span<byte> payload = rented.AsSpan(0, payloadBytes);
            buffer.Slice(WorldGatewayProtocolConstants.RetailWorldPayloadOffsetBytes, payloadBytes).CopyTo(payload);

            ulong dosResponse = BinaryPrimitives.ReadUInt64LittleEndian(payload[..WorldGatewayProtocolConstants.RetailAuthSessionDosResponseBytes]);
            uint regionId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(WorldGatewayProtocolConstants.RetailAuthSessionRegionIdOffsetBytes, sizeof(uint)));
            uint battlegroupId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(WorldGatewayProtocolConstants.RetailAuthSessionBattlegroupIdOffsetBytes, sizeof(uint)));
            uint realmId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(WorldGatewayProtocolConstants.RetailAuthSessionRealmIdOffsetBytes, sizeof(uint)));

            byte[] localChallenge32 = GC.AllocateUninitializedArray<byte>(WorldGatewayProtocolConstants.RetailAuthSessionLocalChallenge32Bytes);
            payload.Slice(
                    WorldGatewayProtocolConstants.RetailAuthSessionLocalChallengeOffsetBytes,
                    WorldGatewayProtocolConstants.RetailAuthSessionLocalChallenge32Bytes)
                .CopyTo(localChallenge32);
            byte[] localChallenge4 = GC.AllocateUninitializedArray<byte>(WorldGatewayProtocolConstants.RetailAuthSessionLocalChallenge4Bytes);
            localChallenge32
                .AsSpan(0, WorldGatewayProtocolConstants.RetailAuthSessionLocalChallenge4Bytes)
                .CopyTo(localChallenge4);

            int accountId = 0;
            _ = TryExtractAccountIdFromRetailPayload(payload, out accountId);

            frame = new RetailAuthSessionFrame(
                DosResponse: dosResponse,
                RegionId: regionId,
                BattlegroupId: battlegroupId,
                RealmId: realmId,
                LocalChallenge4: localChallenge4,
                LocalChallenge32: localChallenge32,
                AccountId: accountId,
                RawFrameBytes: fullFrameBytes);

            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static bool TryExtractAccountIdFromRetailPayload(ReadOnlySpan<byte> payload, out int accountId)
    {
        accountId = 0;

        ReadOnlySpan<byte> key = "\"accountId\""u8;
        int keyIndex = payload.IndexOf(key);
        if (keyIndex < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> tail = payload[(keyIndex + key.Length)..];
        int colonIndex = tail.IndexOf((byte)':');
        if (colonIndex < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> value = tail[(colonIndex + 1)..];
        int offset = 0;
        while (offset < value.Length && IsAsciiJsonWhitespace(value[offset]))
        {
            offset++;
        }

        if (offset >= value.Length)
        {
            return false;
        }

        long parsed = 0;
        int digits = 0;
        while (offset < value.Length)
        {
            byte c = value[offset];
            if (c is < (byte)'0' or > (byte)'9')
            {
                break;
            }

            parsed = (parsed * 10) + (c - (byte)'0');
            if (parsed > int.MaxValue)
            {
                return false;
            }

            digits++;
            offset++;
        }

        if (digits == 0 || parsed <= 0)
        {
            return false;
        }

        accountId = (int)parsed;
        return true;
    }

    private static bool IsAsciiJsonWhitespace(byte value) =>
        value == (byte)' ' || value == (byte)'\t' || value == (byte)'\r' || value == (byte)'\n';
}
