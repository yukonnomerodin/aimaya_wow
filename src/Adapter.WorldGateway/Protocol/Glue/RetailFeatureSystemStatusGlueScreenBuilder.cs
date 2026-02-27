namespace Adapter.WorldGateway;

internal static class RetailFeatureSystemStatusGlueScreenBuilder
{
    public static byte[] BuildFrame(uint opcode, bool trinitySemantics = false)
    {
        var payload = new BitPackedBufferWriter(initialCapacity: trinitySemantics ? 224 : 160);

        // First 16 bits
        payload.WriteBit(false); // BpayStoreAvailable
        payload.WriteBit(false); // CharUndeleteEnabled
        payload.WriteBit(false); // CommerceServerEnabled
        payload.WriteBit(false); // PaidCharacterTransfersBetweenBnetAccountsEnabled
        payload.WriteBit(false); // VeteranTokenRedeemWillKick
        payload.WriteBit(false); // WorldTokenRedeemWillKick
        payload.WriteBit(false); // ExpansionPreorderInStore
        payload.WriteBit(false); // KioskModeEnabled
        payload.WriteBit(false); // CompetitiveModeEnabled
        payload.WriteBit(false); // BoostEnabled
        payload.WriteBit(false); // TrialBoostEnabled
        payload.WriteBit(false); // RedeemForBalanceAvailable
        payload.WriteBit(false); // LiveRegionCharacterListEnabled
        payload.WriteBit(false); // LiveRegionCharacterCopyEnabled
        payload.WriteBit(false); // LiveRegionAccountCopyEnabled
        payload.WriteBit(false); // LiveRegionKeyBindingsCopyEnabled

        // Next flag block
        payload.WriteBit(false); // BrowserCrashReporterEnabled
        payload.WriteBit(false); // IsEmployeeAccount
        payload.WriteBit(trinitySemantics); // Optional EuropaTicketSystemStatus
        payload.WriteBit(false); // NameReservationOnly
        payload.WriteBit(false); // Optional LaunchDurationETA
        payload.WriteBit(false); // TimerunningEnabled
        payload.WriteBit(false); // ScriptsDisallowedForBeta
        payload.WriteBit(false); // PlayerIdentityOptionsEnabled
        payload.WriteBit(false); // AccountExportEnabled
        payload.WriteBit(false); // AccountLockedPostExport
        payload.WriteBits(0, 11); // RealmHiddenAlert sized c-string bits size
        payload.WriteBit(trinitySemantics); // BNSendWhisperUseV2Services
        payload.WriteBit(trinitySemantics); // BNSendGameDataUseV2Services
        payload.WriteBit(false); // CharacterSelectListModeRealmless
        payload.WriteBit(false); // WowTokenLimitedMode
        payload.WriteBit(false); // NavBarEnabled
        payload.WriteBit(false); // GlobalUserGeneratedContentMuteEnabled
        payload.WriteBit(false); // AccountUserGeneratedContentIsRisky
        payload.FlushBits();

        if (trinitySemantics)
        {
            // Trinity writes EuropaTicketConfig immediately after the bit block when present.
            payload.WriteBit(false); // TicketsEnabled
            payload.WriteBit(false); // BugsEnabled
            payload.WriteBit(false); // ComplaintsEnabled
            payload.WriteBit(false); // SuggestionsEnabled
            payload.FlushBits();

            payload.WriteUInt32LE(10); // ThrottleState.MaxTries
            payload.WriteUInt32LE(60000); // ThrottleState.PerMilliseconds
            payload.WriteUInt32LE(1); // ThrottleState.TryCount
            payload.WriteUInt32LE(111111); // ThrottleState.LastResetTimeBeforeNow

            payload.WriteUInt32LE(0); // ExpensiveThrottleState.MaxTries
            payload.WriteUInt32LE(0); // ExpensiveThrottleState.PerMilliseconds
            payload.WriteUInt32LE(0); // ExpensiveThrottleState.TryCount
            payload.WriteUInt32LE(0); // ExpensiveThrottleState.LastResetTimeBeforeNow
        }

        payload.WriteUInt32LE(0); // CommercePricePollTimeSeconds
        payload.WriteUInt32LE(0); // KioskSessionDurationMinutes
        payload.WriteInt64LE(0); // RedeemForBalanceAmount
        payload.WriteInt32LE(50); // MaxCharactersOnThisRealm
        payload.WriteUInt32LE(0); // LiveRegionCharacterCopySourceRegions size
        payload.WriteInt32LE(0); // ActiveBoostType
        payload.WriteInt32LE(0); // TrialBoostType
        payload.WriteInt32LE(0); // MinimumExpansionLevel
        payload.WriteInt32LE(2); // MaximumExpansionLevel
        payload.WriteInt32LE(0); // ContentSetID
        payload.WriteUInt32LE(0); // DisabledGameModes size
        payload.WriteUInt32LE(0); // GameRules size
        payload.WriteUInt32LE(1); // AvailableGameModeIDs size
        payload.WriteInt32LE(0); // ActiveTimerunningSeasonID
        payload.WriteInt32LE(0); // RemainingTimerunningSeasonSeconds
        payload.WriteInt32LE(86400); // TimerunningConversionMinCharacterAge
        payload.WriteInt32LE(-1); // TimerunningConversionMaxSeasonID
        payload.WriteInt16LE(50); // MaxPlayerGuidLookupsPerRequest
        payload.WriteInt16LE(600); // NameLookupTelemetryInterval
        payload.WriteUInt32LE(10); // NotFoundCacheTimeSeconds
        payload.WriteUInt32LE(0); // DebugTimeEvents size
        payload.WriteInt32LE(0); // MostRecentTimeEventID
        payload.WriteUInt32LE(0); // EventRealmQueues
        payload.WriteInt32LE(8); // AvailableGameModeIDs[0]

        return RetailEnvelopeBuilder.BuildRetailWorldFrame(opcode, payload.WrittenSpan);
    }
}
