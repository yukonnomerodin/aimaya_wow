namespace Adapter.WorldGateway;

/// <summary>
/// Centralized opcode catalog for WorldGateway protocol translation.
/// Keep numeric values here and reference from runtime components.
/// </summary>
internal static class WorldGatewayOpcodes
{
    // Retail CMSG opcodes (client -> gateway -> upstream world).
    internal const uint RetailCmsgAuthSession = 0x0041_0001;
    internal const uint RetailCmsgEnterEncryptedModeAck = 0x0041_0005;
    internal const uint RetailCmsgPing = 0x0041_0006;
    internal const uint RetailCmsgLogDisconnect = 0x0041_0007;
    internal const uint RetailCmsgDbQueryBulk = 0x0040_0010;
    internal const uint RetailCmsgHotfixRequest = 0x0040_0011;
    internal const uint RetailCmsgBattlePayGetProductList = 0x0040_00E9;
    internal const uint RetailCmsgBattlePayGetPurchaseList = 0x0040_00EA;
    internal const uint RetailCmsgGetUndeleteCharacterCooldownStatus = 0x0040_010F;
    internal const uint RetailCmsgUpdateVasPurchaseStates = 0x0040_0123;
    internal const uint RetailCmsgSocialContractRequest = 0x0040_0176;
    internal const uint RetailCmsgQuickJoinAutoAcceptRequests = 0x0040_0132;
    internal const uint RetailCmsgGetLastCatalogFetch = 0x0029_0036;
    internal const uint RetailCmsgServerTimeOffsetRequest = 0x0040_00CA;
    internal const uint RetailCmsgBattlenetRequest = 0x0040_0124;
    internal const uint RetailCmsgEnumCharacters = 0x0040_0014;
    internal const uint RetailCmsgWarden3Data = 0x0040_0018;
    internal const uint RetailCmsgAddonList = 0x0040_0004;
    internal const uint RetailCmsgKeepAlive = 0x0040_00AB;
    internal const uint RetailCmsgTimeSyncResponse = 0x003E_005C;

    // Retail SMSG opcodes (gateway <- upstream world -> client).
    internal const uint RetailSmsgAuthResponse = 0x0042_0001;
    internal const uint RetailSmsgAuthResponseSweepStart = 0x0042_0000;
    internal const int RetailSmsgAuthResponseSweepCount = 0x0101;
    internal const uint RetailSmsgAuthChallenge = 0x0049_0000;
    internal const uint RetailSmsgPong = 0x0049_0009;
    internal const uint RetailSmsgCompressedPacket = 0x0049_000D;
    internal const uint RetailSmsgEnterEncryptedModeDefault = 0x0049_0004;
    internal const uint RetailSmsgTimeSyncRequest = 0x005A_0000;
    internal const uint RetailSmsgFeatureSystemStatusGlueScreen = 0x0042_0063;
    internal const uint RetailSmsgMirrorVars = 0x0042_036A;
    internal const uint RetailSmsgSetTimeZoneInformation = 0x0042_0121;
    internal const uint RetailSmsgEnumCharactersResult = 0x0042_0018;
    internal const uint RetailSmsgWarden3Data = 0x0042_000B;
    internal const uint RetailSmsgAddonListRequest = 0x0042_00EA;
    internal const uint RetailSmsgCacheVersion = 0x0046_000E;
    internal const uint RetailSmsgDbReply = 0x0046_0000;
    internal const uint RetailSmsgAvailableHotfixes = 0x0046_0001;
    internal const uint RetailSmsgHotfixConnect = 0x0046_0003;
    internal const uint RetailSmsgAccountDataTimes = 0x0042_01B4;
    internal const uint RetailSmsgServerTimeOffset = 0x0042_01BE;
    internal const uint RetailSmsgTutorialFlags = 0x0042_0266;
    internal const uint RetailSmsgAccountItemCollectionData = 0x0042_035B;
    internal const uint RetailSmsgBattleNetResponse = 0x0042_02AD;
    internal const uint RetailSmsgBattleNetConnectionStatus = 0x0042_02AF;
    internal const uint RetailSmsgUndeleteCooldownStatusResponse = 0x0042_0274;
    internal const uint RetailSmsgSocialContractRequestResponse = 0x0042_0323;
    internal const uint RetailSmsgAuthSequencePrelude = 0x4077_0E75;

    // AzerothCore CMSG opcodes (gateway -> AC world).
    internal const uint AcoreCmsgAuthSession = 0x0000_01ED;
    internal const uint AcoreCmsgCharEnum = 0x0000_0037;
    internal const uint AcoreCmsgPing = 0x0000_01DC;
    internal const uint AcoreCmsgWardenData = 0x0000_02E7;
    internal const uint AcoreCmsgTimeSyncResp = 0x0000_0391;
    internal const uint AcoreCmsgKeepAlive = 0x0000_0407;

    // AzerothCore SMSG opcodes (AC world -> gateway).
    internal const ushort AcoreSmsgAuthChallenge = 0x01EC;
    internal const ushort AcoreSmsgAuthResponse = 0x01EE;
    internal const ushort AcoreSmsgCharEnum = 0x003B;
    internal const ushort AcoreSmsgPong = 0x01DD;
    internal const ushort AcoreSmsgTimeSyncRequest = 0x0390;
    internal const ushort AcoreSmsgWardenData = 0x02E6;
    internal const ushort AcoreSmsgAddonInfo = 0x02EF;
    internal const ushort AcoreSmsgClientCacheVersion = 0x04AB;
    internal const ushort AcoreSmsgTutorialFlags = 0x00FD;
}
