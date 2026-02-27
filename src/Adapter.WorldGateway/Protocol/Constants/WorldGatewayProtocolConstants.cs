namespace Adapter.WorldGateway;

/// <summary>
/// Shared protocol constants that are not opcode values.
/// </summary>
internal static class WorldGatewayProtocolConstants
{
    internal const uint TrinityCompressionAdlerSeed = 0x9827D8F1;
    internal const int AcoreSessionKeyBytes = 40;
    internal const int AcoreAuthDigestBytes = 20;
    internal const int RetailAuthDigestBytes = 24;
    internal const int RetailAuthSessionDosResponseBytes = 8;
    internal const int RetailAuthSessionRegionIdOffsetBytes = 8;
    internal const int RetailAuthSessionBattlegroupIdOffsetBytes = 12;
    internal const int RetailAuthSessionRealmIdOffsetBytes = 16;
    internal const int RetailAuthSessionLocalChallengeOffsetBytes = 20;
    internal const int RetailAuthSessionLocalChallenge32Bytes = 32;
    internal const int RetailAuthSessionLocalChallenge4Bytes = 4;
    internal const int RetailAuthFixedPayloadBytes =
        RetailAuthSessionLocalChallengeOffsetBytes + RetailAuthSessionLocalChallenge32Bytes + RetailAuthDigestBytes;
    internal const ushort AcoreAuthChallengePacketSizeFieldValue = 42;
    internal const int AcoreAuthChallengeFrameBytes = 44;
    internal const int AcoreAuthChallengePayloadOffsetBytes = 4;
    internal const int AcoreAuthChallengePayloadBytes = 40;
    internal const int AcoreAuthChallengeDosChallengeOffsetBytes = AcoreAuthChallengePayloadOffsetBytes + 0;
    internal const int AcoreAuthChallengeAuthSeedOffsetBytes = AcoreAuthChallengePayloadOffsetBytes + 4;
    internal const int AcoreAuthChallengeNewSeedOffsetBytes = AcoreAuthChallengePayloadOffsetBytes + 8;
    internal const int AcoreAuthChallengeNewSeedBytes = 32;
    internal const int RetailAuthChallengeDosBlockBytes = 32;
    internal const int RetailAuthChallengeChallengeBlockBytes = 32;
    internal const int RetailAuthChallengeTrailingFlagBytes = 1;
    internal const int RetailAuthChallengePayloadBytes =
        RetailAuthChallengeDosBlockBytes + RetailAuthChallengeChallengeBlockBytes + RetailAuthChallengeTrailingFlagBytes;
    internal const int RetailAuthChallengeBodyBytes = RetailWorldOpcodeBytes + RetailAuthChallengePayloadBytes;
    internal const int RetailAuthChallengePayloadChallengeBlockOffsetBytes = RetailAuthChallengeDosBlockBytes;
    internal const int RetailAuthChallengePayloadTrailingFlagOffsetBytes = RetailAuthChallengePayloadBytes - 1;
    internal const int RetailAccountDataTimesCount = 20;
    internal const int RetailTutorialValuesCount = 8;
    internal const int TrinityCompressionThresholdBytes = 0x400;
    internal const int RetailWorldFrameOuterHeaderBytes = 16;
    internal const int RetailWorldOpcodeBytes = 4;
    internal const int RetailWorldPayloadOffsetBytes = RetailWorldFrameOuterHeaderBytes + RetailWorldOpcodeBytes;
    internal const int RetailWorldFrameMinBytes = RetailWorldPayloadOffsetBytes;
    internal const int RetailWorldFrameTagBytes = 12;
    internal const int RetailWorldFrameNonceBytes = 12;
    internal const int RetailWorldFrameMaxBytes = 16 * 1024 * 1024;
    internal const int RetailPostAuthClientMaxFrameBytes = 4 * 1024 * 1024;
    internal const int AcorePostAuthServerMaxPacketBytes = 16 * 1024 * 1024;
    internal const string RetailWorldPacketCryptNonceLayoutCounterLeMagicLe = "counter_le_magic_le";
    internal const string RetailWorldPacketCryptNonceLayoutCounterBeMagicLe = "counter_be_magic_le";
    internal const string RetailWorldPacketCryptNonceLayoutMagicLeCounterBe = "magic_le_counter_be";
    internal const string RetailWorldPacketCryptDefaultNonceLayout = RetailWorldPacketCryptNonceLayoutCounterLeMagicLe;
    internal const string RetailWorldPacketCryptDefaultServerNonceMagic = "srvr";
    internal const string RetailWorldPacketCryptDefaultClientNonceMagic = "clnt";
    internal const uint RetailWorldPacketCryptServerNonceMagicUInt32 = 0x52565253; // "SRVR"
    internal const uint RetailWorldPacketCryptClientNonceMagicUInt32 = 0x544E4C43; // "CLNT"
    internal const int AuthResponseReplayOptionalBitsOffset = 4;
    internal const byte AuthResponseReplaySuccessInfoMask = 0x80;
    internal const byte AuthResponseReplayWaitInfoMask = 0x40;
    internal const byte AuthResponseReplaySuccessInfoCurrentBuildMask = 0x04;
    internal const uint AuthResponseReplayCurrentBuildValue = 66102;
    internal const int AuthResponseReplayWaitInfoPayloadBytes = 10;
    internal const int AuthResponseReplaySuccessInfoOffset = 5;
    internal const int AuthResponseReplayTopVirtualRealmAddressOffset = AuthResponseReplaySuccessInfoOffset + 0;
    internal const int AuthResponseReplayActiveExpansionLevelOffset = AuthResponseReplaySuccessInfoOffset + 12;
    internal const int AuthResponseReplayAccountExpansionLevelOffset = AuthResponseReplaySuccessInfoOffset + 13;
    internal const int AuthResponseReplayAvailableClassesCountOffset = AuthResponseReplaySuccessInfoOffset + 18;
    internal const int AuthResponseReplayClassMatrixStartOffset = AuthResponseReplaySuccessInfoOffset + 38;
    internal const uint AuthResponseReplayMaxAvailableClassesRows = 4096;
    internal const uint AuthResponseReplayMaxClassRowsPerRace = 4096;
    internal const int AuthResponseReplayTimeFieldOffset = AuthResponseReplaySuccessInfoOffset + 30;
    internal const int AuthResponseReplayGameTimeFixedBytes = 12;
    internal const int AuthResponseReplayGameTimeFlagsBytes = 1;
    internal const int RetailGlueDbQueryBulkMinPayloadBytes = 6;
    internal const int RetailGlueDbQueryBulkTableHashBytes = 4;
    internal const int RetailGlueDbQueryBulkQueryCountBits = 13;
    internal const int RetailGlueDbQueryBulkMaxRecords = 4096;
    internal const int RetailGlueBattlenetRequestMinPayloadBytes = 24;
    internal const int RetailGlueBattlenetRequestMethodTypeOffsetBytes = 0;
    internal const int RetailGlueBattlenetRequestMethodTypeBytes = 8;
    internal const int RetailGlueBattlenetRequestObjectIdOffsetBytes = 8;
    internal const int RetailGlueBattlenetRequestObjectIdBytes = 8;
    internal const int RetailGlueBattlenetRequestTokenOffsetBytes = 16;
    internal const int RetailGlueBattlenetRequestTokenBytes = 4;
    internal const int RetailGlueBattlenetRequestProtoSizeOffsetBytes = 20;
    internal const int RetailGlueBattlenetRequestProtoSizeBytes = 4;

    internal static uint BuildRetailVirtualRealmAddress(uint acoreRealmId)
    {
        uint realmId = acoreRealmId != 0 ? acoreRealmId : 1u;
        return (1u << 24) | (1u << 16) | (realmId & 0xFFFFu);
    }
}
