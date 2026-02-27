using System.Buffers.Binary;

namespace Adapter.WorldGateway;

internal static class RetailGlueRequestParsers
{
    public static bool TryParseDbQueryBulk(
        ReadOnlySpan<byte> payload,
        out ParsedDbQueryBulk query,
        out string? error)
    {
        query = default;
        error = null;

        if (payload.Length < WorldGatewayProtocolConstants.RetailGlueDbQueryBulkMinPayloadBytes)
        {
            error = $"DB_QUERY_BULK payload too short: {payload.Length}.";
            return false;
        }

        uint tableHash = BinaryPrimitives.ReadUInt32LittleEndian(
            payload[..WorldGatewayProtocolConstants.RetailGlueDbQueryBulkTableHashBytes]);
        ReadOnlySpan<byte> packed = payload[WorldGatewayProtocolConstants.RetailGlueDbQueryBulkTableHashBytes..];
        int bitOffset = 0;
        if (!TryReadBitsMsbFirst(
                packed,
                ref bitOffset,
                WorldGatewayProtocolConstants.RetailGlueDbQueryBulkQueryCountBits,
                out ulong queryCountRaw))
        {
            error = "Failed to read DB_QUERY_BULK query count.";
            return false;
        }

        if (queryCountRaw > WorldGatewayProtocolConstants.RetailGlueDbQueryBulkMaxRecords)
        {
            error = $"DB_QUERY_BULK query count is out of range: {queryCountRaw}.";
            return false;
        }

        int queryCount = (int)queryCountRaw;
        int byteOffset = (bitOffset + 7) / 8;
        int bytesNeeded = checked(queryCount * sizeof(int));
        if (packed.Length - byteOffset < bytesNeeded)
        {
            error = $"DB_QUERY_BULK payload truncated. QueryCount={queryCount}, Available={packed.Length - byteOffset}, Needed={bytesNeeded}.";
            return false;
        }

        int[] recordIds = GC.AllocateUninitializedArray<int>(queryCount);
        for (int i = 0; i < queryCount; i++)
        {
            int offset = byteOffset + (i * sizeof(int));
            recordIds[i] = BinaryPrimitives.ReadInt32LittleEndian(packed.Slice(offset, sizeof(int)));
        }

        query = new ParsedDbQueryBulk(tableHash, recordIds);
        return true;
    }

    public static bool TryParseBattlenetRequest(
        ReadOnlySpan<byte> payload,
        out ParsedBattlenetRequest request,
        out string? error)
    {
        request = default;
        error = null;

        if (payload.Length < WorldGatewayProtocolConstants.RetailGlueBattlenetRequestMinPayloadBytes)
        {
            error = $"CMSG_BATTLENET_REQUEST payload too short: {payload.Length}.";
            return false;
        }

        ulong methodType = BinaryPrimitives.ReadUInt64LittleEndian(
            payload.Slice(
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestMethodTypeOffsetBytes,
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestMethodTypeBytes));
        ulong objectId = BinaryPrimitives.ReadUInt64LittleEndian(
            payload.Slice(
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestObjectIdOffsetBytes,
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestObjectIdBytes));
        uint token = BinaryPrimitives.ReadUInt32LittleEndian(
            payload.Slice(
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestTokenOffsetBytes,
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestTokenBytes));
        uint protoSize = BinaryPrimitives.ReadUInt32LittleEndian(
            payload.Slice(
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestProtoSizeOffsetBytes,
                WorldGatewayProtocolConstants.RetailGlueBattlenetRequestProtoSizeBytes));
        if (payload.Length < WorldGatewayProtocolConstants.RetailGlueBattlenetRequestMinPayloadBytes + protoSize)
        {
            error = $"CMSG_BATTLENET_REQUEST payload truncated. ProtoSize={protoSize}, PayloadBytes={payload.Length}.";
            return false;
        }

        request = new ParsedBattlenetRequest(methodType, objectId, token);
        return true;
    }

    private static bool TryReadBitsMsbFirst(ReadOnlySpan<byte> payload, ref int bitOffset, int bitCount, out ulong value)
    {
        value = 0;
        if (bitCount < 0 || bitCount > 64)
        {
            return false;
        }

        for (int i = 0; i < bitCount; i++)
        {
            int absoluteBit = bitOffset + i;
            int byteIndex = absoluteBit / 8;
            if (byteIndex >= payload.Length)
            {
                return false;
            }

            int bitIndexInByte = 7 - (absoluteBit % 8);
            int bit = (payload[byteIndex] >> bitIndexInByte) & 1;
            value = (value << 1) | (uint)bit;
        }

        bitOffset += bitCount;
        return true;
    }
}

internal readonly record struct ParsedDbQueryBulk(uint TableHash, int[] RecordIds);
internal readonly record struct ParsedBattlenetRequest(ulong MethodType, ulong ObjectId, uint Token);
