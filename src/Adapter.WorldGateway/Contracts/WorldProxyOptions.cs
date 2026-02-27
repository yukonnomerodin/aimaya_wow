using System.ComponentModel.DataAnnotations;

namespace Adapter.WorldGateway;

public sealed class WorldProxyOptions
{
    public const string SectionName = "WorldProxy";

    public string ListenAddress { get; init; } = "0.0.0.0";

    [Range(1, 65535)]
    public int ListenPort { get; init; } = 8086;

    [Range(1, 8192)]
    public int Backlog { get; init; } = 1024;

    public string UpstreamAddress { get; init; } = "127.0.0.1";

    [Range(1, 65535)]
    public int UpstreamPort { get; init; } = 8085;

    [Range(100, 60000)]
    public int UpstreamConnectTimeoutMs { get; init; } = 3000;

    [Range(1024, 1024 * 1024)]
    public int ReaderBufferSize { get; init; } = 64 * 1024;

    [Range(256, 128 * 1024)]
    public int MinimumReadSize { get; init; } = 2048;

    public bool EnableRetailConnectionInitializer { get; init; } = true;

    [Range(100, 10000)]
    public int InitializerTimeoutMs { get; init; } = 3000;

    [Range(100, 10000)]
    public int EnterEncryptedModeAckTimeoutMs { get; init; } = 1500;

    public bool EnterEncryptedModeAckGateEnabled { get; init; } = false;

    public string BootstrapFlushTriggerSource { get; init; } = "ack";

    [Range(0, 10000)]
    public int BootstrapFlushTriggerFallbackTimeoutMs { get; init; } = 0;

    public bool SuppressPostAuthBootstrapForProbe { get; init; } = false;

    public bool ProbeBareAuthResponseOnly { get; init; } = false;

    public bool ProbeAuthResponseResultOnly { get; init; } = false;

    [Range(0, 4294967295)]
    public long ProbeAuthResponseResultOnlyCode { get; init; } = 0;

    public bool ProbeAuthResponseMinimalSuccessNoAccountData { get; init; } = false;

    public bool ProbeAuthResponseTwwAccountDataProfile { get; init; } = false;

    public bool ProbeAuthResponseTwwAddResultPrefix { get; init; } = false;

    public bool ProbeAuthResponseForceWaitInfoPresent { get; init; } = false;

    public bool ProbeAuthResponseForceCurrentBuildPresent { get; init; } = false;

    [Range(1, 13)]
    public int ProbeAuthResponseAvailableClassesCardinality { get; init; } = 1;

    [Range(0, 1024)]
    public int ProbeAuthResponseTwwClassMatrixRows { get; init; } = 0;

    public bool ProbeAuthResponseTwwUseAcoreExpansionLevels { get; init; } = false;

    public bool ProbeInsertRetailSequencePreludeBeforeAuthResponse { get; init; } = false;

    public bool ProbeInsertRetailSequencePreludeAfterAuthResponse { get; init; } = false;

    public bool ProbeReorderFirstDeferredFrameAfterPrelude { get; init; } = false;

    public bool ProbeFeatureSystemStatusGlueScreenTrinitySemantics { get; init; } = false;

    public bool ProbeCompressAuthResponseAsSmsgCompressedPacket { get; init; } = false;

    public bool ProbeCompressedAuthResponseForceEnvelope { get; init; } = false;

    public bool ProbeCompressedAuthResponseUseRawDeflate { get; init; } = false;

    public bool ProbeCompressedAuthResponseUseStatefulDeflateSyncFlush { get; init; } = false;

    [Range(-1, 9)]
    public int ProbeCompressedAuthResponseRawDeflateLevel { get; init; } = -1;

    public bool ProbeCompressedAuthResponseChecksumPayloadOnly { get; init; } = false;

    [Range(0, 4294967295)]
    public long ProbeCompressedAuthResponseChecksumSeed { get; init; } = 0x9827D8F1u;

    public bool ProbeCompressedAuthResponseCompressedChecksumIncludeMetadata { get; init; } = false;

    public bool ProbeExplicitBootstrapFlushMarker { get; init; } = false;

    public string ProbeRetailSequencePreludePayloadHex { get; init; } = string.Empty;

    public string ProbeAuthResponseOpcodeOverride { get; init; } = string.Empty;

    public string ProbeAuthResponseReplayPayloadHexPath { get; init; } = string.Empty;
    public string ProbeAuthResponseReplayCompressedPayloadHexPath { get; init; } = string.Empty;

    public bool ProbeAuthResponseReplayPatchTimeToNow { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchExpansionLevelsToRuntimeAccount { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchClassMatrixExpansionTripletsToRuntimeAccount { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchClassMatrixCardinalityToRuntimeSubset { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchCurrentBuildPresent { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchWaitInfoPresent { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchVirtualRealmEntryToRuntimeRealm { get; init; } = false;

    public bool ProbeAuthResponseReplayPatchTopVirtualRealmAddressToRuntimeRealm { get; init; } = false;

    public bool ProbeAuthResponseReplayBisectionResultOnlyErrorOk { get; init; } = false;

    public string ProbeSetTimeZoneInformationPayloadHexPath { get; init; } = string.Empty;

    public string ProbeFeatureSystemStatusGlueScreenPayloadHexPath { get; init; } = string.Empty;

    public string ProbeMirrorVarsPayloadHexPath { get; init; } = string.Empty;

    public string ProbeCacheVersionPayloadHexPath { get; init; } = string.Empty;

    public string ProbeAvailableHotfixesPayloadHexPath { get; init; } = string.Empty;

    public string ProbeAccountDataTimesPayloadHexPath { get; init; } = string.Empty;

    public string ProbeTutorialFlagsPayloadHexPath { get; init; } = string.Empty;

    public string ProbeBattleNetConnectionStatusPayloadHexPath { get; init; } = string.Empty;

    public string ProbeFirstDeferredFrameParityFixturePath { get; init; } = string.Empty;

    public bool ProbeRetailAuthChallengeCountAsPreAckWorldFrame { get; init; } = false;

    public bool ProbeRetailAuthSessionCountAsPreAckClientFrame { get; init; } = false;

    public bool ProbeAuthResponseFuzzerEnabled { get; init; } = false;

    [Range(0, 1_000_000)]
    public int ProbeAuthResponseFuzzerIteration { get; init; } = 0;

    public string ProbeAuthResponseFuzzerPlan { get; init; } = "M1-FUZZ-500";

    public bool EnterEncryptedModeSignatureFirst { get; init; } = false;

    [Range(0, 1024)]
    public int EnterEncryptedModeRegionGroup { get; init; } = 1;

    public bool EnterEncryptedModeIncludeRegionGroup { get; init; } = true;

    public bool EnterEncryptedModeEnabled { get; init; } = true;

    public bool EnterEncryptedModeEnabledAsByte { get; init; } = false;

    public string EnterEncryptedModeOpcode { get; init; } = "0x00490004";

    public bool EnterEncryptedModePreferBnetKeyData { get; init; } = true;

    public bool EnableRetailWorldPacketCryptOnAck { get; init; } = false;

    public bool ForwardAcoreWardenAsRetailWarden3Data { get; init; } = false;

    public bool ForwardAcoreAddonInfoAsRetailAddonListRequest { get; init; } = false;

    public bool ForwardAcoreTutorialFlagsAsRetailTutorialFlags { get; init; } = false;

    public bool ControlledUnlockEmptyCharEnumEnabled { get; init; } = false;

    [Range(0, 5000)]
    public int GlueSyntheticCharEnumKickMinIntervalMs { get; init; } = 0;

    [Range(0, 120000)]
    public int ReconnectCooldownMs { get; init; } = 0;

    [Range(0, int.MaxValue)]
    public int RetailWorldPacketCryptServerInitialCounter { get; init; } = 0;

    public bool RetailWorldPacketCryptUseSizeAsAad { get; init; } = false;

    [Range(2, 4)]
    public int RetailWorldPacketCryptAadSizeBytes { get; init; } = 4;

    public bool RetailWorldPacketCryptUseEmptyAad { get; init; } = false;

    public string RetailWorldPacketCryptNonceLayout { get; init; } = "counter_le_magic_le";

    public string RetailWorldPacketCryptServerNonceMagic { get; init; } = "srvr";

    public string RetailWorldPacketCryptClientNonceMagic { get; init; } = "clnt";

    public string ProbeDropDeferredOpcode { get; init; } = string.Empty;

    public bool EnterEncryptedModeUseGoldenPayload { get; init; } = false;

    public string EnterEncryptedModeGoldenMetadataPath { get; init; } = string.Empty;

    public bool EnterEncryptedModeGoldenPatchRuntimeSignature { get; init; } = false;

    public bool EnterEncryptedModeParityGateEnabled { get; init; } = false;

    public string EnterEncryptedModeParityFixturePath { get; init; } = string.Empty;

    public bool ExposeRetailWorldEncryptKeyInProof { get; init; } = false;

    public bool RetailAuthChallengeRandomizeDosBlock { get; init; } = false;

    [Range(0, int.MaxValue)]
    public int AuthAccountIdFallback { get; init; } = 0;

    public bool EnableAcoreToRetailAuthChallengeBridgeProbe { get; init; } = true;

    public bool EnableRetailToAcoreAuthSessionBridge { get; init; } = true;

    public string AuthDbConnectionString { get; init; } =
        "Server=127.0.0.1;User ID=aimaya;Password=aimaya;Database=acore_auth;SslMode=None;Allow User Variables=True;Treat Tiny As Boolean=False";

    public uint AcoreRealmId { get; init; } = 1;

    public uint AcoreClientBuild { get; init; } = 12340;

    public bool EnableFirstPacketDump { get; init; } = true;

    [Range(16, 1024)]
    public int FirstPacketDumpBytes { get; init; } = 64;

    public bool EnableProofPack { get; init; } = true;

    public bool EnableHandshakeLabReport { get; init; } = true;

    public string ProofPackRootPath { get; init; } = "docs/handshake";
}

