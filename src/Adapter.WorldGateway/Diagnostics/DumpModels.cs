namespace Adapter.WorldGateway;

internal readonly record struct DumpHeaderDecode(
    ushort SizeBE,
    ushort SizeLE,
    ushort OpcodeLE,
    ushort OpcodeBE,
    bool SizeBEMatches);

internal readonly record struct AcoreAuthChallengeDump(
    uint DosChallenge,
    uint AuthSeed,
    string NewSeedHex,
    byte[] NewSeed);

