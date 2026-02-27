namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private sealed partial class AcorePostAuthServerTranslator
    {
        private bool TryApplyAuthResponseCompressionIfNeeded(
            byte[] mapped,
            bool authResponseAlreadyCompressed,
            out byte[] outputMapped,
            out string? error)
        {
            outputMapped = mapped;
            error = null;

            if (!_probeCompressAuthResponseAsSmsgCompressedPacket || authResponseAlreadyCompressed)
            {
                return true;
            }

            if (!RetailCompressedPacketWrapper.TryBuildRetailCompressedPacketFrame(
                    mapped,
                    _probeCompressedAuthResponseForceEnvelope,
                    _probeCompressedAuthResponseUseRawDeflate,
                    _probeCompressedAuthResponseUseStatefulDeflateSyncFlush,
                    _probeCompressedAuthResponseRawDeflateLevel,
                    _probeCompressedAuthResponseChecksumPayloadOnly,
                    _probeCompressedAuthResponseChecksumSeed,
                    _probeCompressedAuthResponseCompressedChecksumIncludeMetadata,
                    _statefulCompressedAuthResponseCompressor,
                    RetailOpcodeSmsgCompressedPacket,
                    TrinityCompressionThresholdBytes,
                    out byte[] compressedAuthResponse,
                    out string? compressionError))
            {
                error = $"Failed to wrap AUTH_RESPONSE as SMSG_COMPRESSED_PACKET: {compressionError ?? "<unknown>"}";
                return false;
            }

            outputMapped = compressedAuthResponse;
            return true;
        }
    }
}
