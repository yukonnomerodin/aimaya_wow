namespace Adapter.WorldGateway;

internal static class RetailEmptyEnumCharactersResultBuilder
{
    public static byte[] BuildFrame(uint opcode)
    {
        // Trinity 12.x EnumCharactersResult layout for empty list.
        // Controlled unlock variant uses permissive unlock metadata to keep character creation UI enabled.
        // This path is used only for AC empty char-list payloads under explicit config flag.
        var payload = new BitPackedBufferWriter(initialCapacity: 320);
        ReadOnlySpan<byte> unlockedRaces =
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
            22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 35, 36, 37
        ];

        payload.WriteBit(true);  // Success
        payload.WriteBit(false); // Realmless
        payload.WriteBit(false); // IsDeletedCharacters
        payload.WriteBit(true);  // IgnoreNewPlayerRestrictions
        payload.WriteBit(false); // IsRestrictedNewPlayer
        payload.WriteBit(true);  // IsNewcomerChatCompleted
        payload.WriteBit(false); // IsRestrictedTrial
        payload.WriteBit(false); // IsAccountLapsedPlayer
        payload.WriteBit(true);  // ClassDisableMask present (Trinity initializes Optional<uint32>)
        payload.WriteBit(false); // ForceCharacterListSort
        payload.FlushBits();

        payload.WriteUInt32LE(0); // Characters size
        payload.WriteUInt32LE(0); // RegionwideCharacters size
        payload.WriteInt32LE(80); // MaxCharacterLevel
        payload.WriteUInt32LE((uint)unlockedRaces.Length); // RaceUnlockData size
        payload.WriteUInt32LE(0); // UnlockedConditionalAppearances size
        payload.WriteUInt32LE(0); // RaceLimitDisables size
        payload.WriteUInt32LE(0); // WarbandGroups size
        payload.WriteUInt32LE(0); // ClassDisableMask value

        for (int i = 0; i < unlockedRaces.Length; i++)
        {
            payload.WriteByte(unlockedRaces[i]); // RaceID
            payload.WriteUInt32LE(1); // ClassUnlocks size
            payload.WriteBit(true);   // HasUnlockedLicense
            payload.WriteBit(true);   // HasUnlockedAchievement
            payload.WriteBit(false);  // HasHeritageArmorUnlockAchievement
            payload.WriteBit(false);  // HideRaceOnClient
            payload.WriteBit(false);  // FactionBalanceDisabled
            payload.FlushBits();

            payload.WriteByte(1);     // ClassID (Warrior)
            payload.WriteUInt32LE(0); // AchievementID
            payload.WriteBit(true);   // HasUnlockedAchievement
            payload.FlushBits();
        }

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }
}
