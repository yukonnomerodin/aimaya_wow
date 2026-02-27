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

        if (buffer.Length < 20)
        {
            return false;
        }

        Span<byte> header20 = stackalloc byte[20];
        buffer.Slice(0, 20).CopyTo(header20);

        uint packetSize = BinaryPrimitives.ReadUInt32LittleEndian(header20[..4]);
        if (packetSize < 4)
        {
            return false;
        }

        int fullFrameBytes = checked(16 + (int)packetSize);
        if (buffer.Length < fullFrameBytes)
        {
            return false;
        }

        uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(header20.Slice(16, 4));
        if (opcode != authSessionOpcode)
        {
            return false;
        }

        int payloadBytes = (int)packetSize - 4;
        if (payloadBytes < retailAuthFixedPayloadBytes)
        {
            return false;
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(payloadBytes);
        try
        {
            Span<byte> payload = rented.AsSpan(0, payloadBytes);
            buffer.Slice(20, payloadBytes).CopyTo(payload);

            ulong dosResponse = BinaryPrimitives.ReadUInt64LittleEndian(payload[..8]);
            uint regionId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(8, 4));
            uint battlegroupId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(12, 4));
            uint realmId = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(16, 4));

            byte[] localChallenge32 = GC.AllocateUninitializedArray<byte>(32);
            payload.Slice(20, 32).CopyTo(localChallenge32);
            byte[] localChallenge4 = GC.AllocateUninitializedArray<byte>(4);
            localChallenge32.AsSpan(0, 4).CopyTo(localChallenge4);

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
