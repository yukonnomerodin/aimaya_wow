namespace Adapter.WorldGateway;

internal static class RetailGluePayloadBuilders
{
    public static byte[] BuildMirrorVarsFrame(uint opcode)
    {
        (string Name, string Value)[] vars =
        [
            ("raidLockoutExtendEnabled", "1"),
            ("bypassItemLevelScalingCode", "0"),
            ("shop2Enabled", "0"),
            ("bpayStoreEnable", "0"),
            ("recentAlliesEnabledClient", "0"),
            ("browserEnabled", "0"),
            ("housingEnableCreateGuildNeighborhood", "0"),
            ("housingEnableDeleteHouse", "0"),
            ("housingServiceEnabled", "0"),
            ("housingEnableMoveHouse", "0"),
            ("housingEnableCreateCharterNeighborhood", "0"),
            ("housingEnableBuyHouse", "0"),
            ("housingMarketEnabled", "0")
        ];

        var payload = new BitPackedBufferWriter(initialCapacity: 384);
        payload.WriteUInt32LE((uint)vars.Length);
        for (int i = 0; i < vars.Length; i++)
        {
            payload.WriteBit(false); // UpdateType
            payload.WriteBits((ulong)vars[i].Name.Length, 24);
            payload.WriteBits((ulong)vars[i].Value.Length, 24);
            payload.FlushBits();
            payload.WriteAscii(vars[i].Name);
            payload.WriteAscii(vars[i].Value);
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildCacheVersionFrame(uint opcode, byte[]? acoreCacheVersionPayload)
    {
        ReadOnlySpan<byte> payload = acoreCacheVersionPayload is { Length: 4 }
            ? acoreCacheVersionPayload
            : [0, 0, 0, 0];
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload);
    }

    public static byte[] BuildAvailableHotfixesFrame(uint opcode, uint acoreRealmId)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 8);
        payload.WriteInt32LE(unchecked((int)WorldGatewayProtocolConstants.BuildRetailVirtualRealmAddress(acoreRealmId))); // VirtualRealmAddress
        payload.WriteUInt32LE(0); // Hotfixes count
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildAccountDataTimesFrame(uint opcode, int accountDataTimesCount)
    {
        // Trinity serialization:
        // packed ObjectGuid (empty => two zero mask bytes) + int64 server time + Nx int64 account timestamps.
        var payload = new BitPackedBufferWriter(initialCapacity: 2 + 8 + (accountDataTimesCount * 8));
        payload.WriteByte(0); // ObjectGuid mask[0] for ObjectGuid::Empty
        payload.WriteByte(0); // ObjectGuid mask[1] for ObjectGuid::Empty
        payload.WriteInt64LE(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); // ServerTime
        for (int i = 0; i < accountDataTimesCount; i++)
        {
            payload.WriteInt64LE(0); // AccountTimes[i]
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildTutorialFlagsFrame(uint opcode, byte[]? acoreTutorialFlagsPayload, int tutorialValuesByteSize)
    {
        ReadOnlySpan<byte> payload = acoreTutorialFlagsPayload is { Length: var size } && size == tutorialValuesByteSize
            ? acoreTutorialFlagsPayload
            : new byte[tutorialValuesByteSize];
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload);
    }

    public static byte[] BuildBattleNetConnectionStatusFrame(uint opcode, byte state, bool suppressNotification)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 1);
        payload.WriteBits((ulong)(state & 0x03), 2); // State
        payload.WriteBit(suppressNotification); // SuppressNotification
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildAccountItemCollectionDataFrame(uint opcode)
    {
        // Trinity 12.x CollectionPackets::AccountItemCollectionData::Write
        // with empty warband-scene collection.
        var payload = new BitPackedBufferWriter(initialCapacity: 10);
        payload.WriteUInt32LE(0); // Unknown1110_1
        payload.WriteByte(7); // Type = ItemCollectionType::WarbandScene
        payload.WriteUInt32LE(0); // Items count
        payload.WriteBit(false); // Unknown1110_2
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildSocialContractRequestResponseFrame(uint opcode, bool showSocialContract)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 1);
        payload.WriteBit(showSocialContract);
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildUndeleteCooldownStatusResponseFrame(
        uint opcode,
        uint maxCooldownSeconds,
        uint currentCooldownSeconds,
        bool onCooldown)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 9);
        payload.WriteUInt32LE(maxCooldownSeconds);
        payload.WriteUInt32LE(currentCooldownSeconds);
        payload.WriteBit(onCooldown);
        payload.FlushBits();
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildDbReplyFrame(
        uint opcode,
        uint tableHash,
        int recordId,
        uint timestamp,
        byte status,
        ReadOnlySpan<byte> data)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 20 + data.Length);
        payload.WriteUInt32LE(tableHash);
        payload.WriteInt32LE(recordId);
        payload.WriteUInt32LE(timestamp);
        payload.WriteBits((ulong)(status & 0x07), 3); // DB2Manager::HotfixRecord::Status (3 bits)
        payload.WriteUInt32LE((uint)data.Length);
        if (!data.IsEmpty)
        {
            payload.WriteBytes(data);
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildBattleNetResponseFrame(
        uint opcode,
        ulong methodType,
        ulong objectId,
        uint token,
        uint statusCode,
        ReadOnlySpan<byte> data)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 28 + data.Length);
        payload.WriteUInt32LE(statusCode);
        payload.WriteUInt64LE(methodType);
        payload.WriteUInt64LE(objectId);
        payload.WriteUInt32LE(token);
        payload.WriteUInt32LE((uint)data.Length);
        if (!data.IsEmpty)
        {
            payload.WriteBytes(data);
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildServerTimeOffsetFrame(uint opcode, long unixTimeSeconds)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: sizeof(long));
        payload.WriteInt64LE(unixTimeSeconds);
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

    public static byte[] BuildHotfixConnectFrame(uint opcode)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: 8);
        payload.WriteUInt32LE(0); // Hotfixes count
        payload.WriteUInt32LE(0); // HotfixContent size
        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }

}
