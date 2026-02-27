namespace Adapter.WorldGateway;

/// <summary>
/// Shared protocol constants that are not opcode values.
/// </summary>
internal static class WorldGatewayProtocolConstants
{
    internal const uint TrinityCompressionAdlerSeed = 0x9827D8F1;
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

    internal static uint BuildRetailVirtualRealmAddress(uint acoreRealmId)
    {
        uint realmId = acoreRealmId != 0 ? acoreRealmId : 1u;
        return (1u << 24) | (1u << 16) | (realmId & 0xFFFFu);
    }
}
