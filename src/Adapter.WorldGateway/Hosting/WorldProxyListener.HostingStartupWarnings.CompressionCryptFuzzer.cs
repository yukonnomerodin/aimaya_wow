using System;
using Microsoft.Extensions.Logging;

namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private void LogStartupProbeCompressionCryptAndParityWarnings()
    {
        if (_options.ProbeCompressAuthResponseAsSmsgCompressedPacket)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: first post-ACK SMSG_AUTH_RESPONSE is wrapped as SMSG_COMPRESSED_PACKET when payload exceeds Trinity threshold (>0x{Threshold:X}).",
                WorldGatewayProtocolConstants.TrinityCompressionThresholdBytes);

            if (_options.ProbeCompressedAuthResponseForceEnvelope)
            {
                _logger.LogWarning(
                    "WorldProxy probe enabled: compressed AUTH_RESPONSE envelope is forced even when payload is at/below Trinity compression threshold.");
            }
        }

        if (_options.ProbeCompressedAuthResponseUseRawDeflate)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE payload uses raw deflate stream (no zlib wrapper).");
        }

        if (_options.ProbeCompressedAuthResponseUseStatefulDeflateSyncFlush)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE payload uses stateful raw-deflate stream with sync-flush boundaries.");
        }

        if (_options.ProbeCompressAuthResponseAsSmsgCompressedPacket && _options.ProbeCompressedAuthResponseUseRawDeflate)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE raw-deflate level={RawDeflateLevel} (Trinity parity target: 1).",
                RetailCompressionCodec.NormalizeDeflateLevel(_options.ProbeCompressedAuthResponseRawDeflateLevel));
        }

        if (_options.ProbeCompressedAuthResponseChecksumPayloadOnly)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE uncompressed Adler checksum uses payload-only scope (opcode excluded).");
        }

        if (_options.ProbeCompressAuthResponseAsSmsgCompressedPacket)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE checksum seed=0x{ChecksumSeed:X8}.",
                RetailCompressionCodec.NormalizeChecksumSeed(
                    _options.ProbeCompressedAuthResponseChecksumSeed,
                    WorldGatewayProtocolConstants.TrinityCompressionAdlerSeed));
        }

        if (_options.ProbeCompressedAuthResponseCompressedChecksumIncludeMetadata)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: compressed AUTH_RESPONSE compressed Adler checksum includes metadata prefix (uncompressed_size + uncompressed_adler).");
        }

        if (_options.EnterEncryptedModeUseGoldenPayload && _options.EnterEncryptedModeGoldenPatchRuntimeSignature)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: ENTER_ENCRYPTED_MODE golden payload will be patched with runtime signature.");
        }

        if (_options.EnterEncryptedModeParityGateEnabled)
        {
            _logger.LogWarning(
                "WorldProxy parity gate enabled for ENTER_ENCRYPTED_MODE payload (FixturePath={FixturePath}).",
                string.IsNullOrWhiteSpace(_options.EnterEncryptedModeParityFixturePath)
                    ? "<auto:docs/handshake/runlogs/enter_encrypted_mode.golden*.hex|json>"
                    : _options.EnterEncryptedModeParityFixturePath);

            if (_options.EnterEncryptedModeUseGoldenPayload && _options.EnterEncryptedModeGoldenPatchRuntimeSignature)
            {
                _logger.LogWarning(
                    "WorldProxy parity gate in runtime-signature mode: ENTER_ENCRYPTED_MODE signature bytes are excluded from fixture diff; gate enforces structural parity only.");
            }
            else if (!_options.EnterEncryptedModeUseGoldenPayload)
            {
                _logger.LogWarning(
                    "WorldProxy parity gate in runtime-generated mode: ENTER_ENCRYPTED_MODE signature bytes are excluded from fixture diff; gate enforces structural parity only.");
            }
        }

        if (!string.IsNullOrWhiteSpace(_options.ProbeFirstDeferredFrameParityFixturePath))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: first deferred frame parity fixture configured (FixturePath={FixturePath}).",
                _options.ProbeFirstDeferredFrameParityFixturePath);
        }

        if (_options.RetailWorldPacketCryptServerInitialCounter != 0)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt server initial counter override active ({Counter}).",
                _options.RetailWorldPacketCryptServerInitialCounter);
        }

        if (_options.RetailWorldPacketCryptUseSizeAsAad)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt uses plaintext size field as AES-GCM AAD (AadSizeBytes={AadSizeBytes}).",
                _options.RetailWorldPacketCryptAadSizeBytes);
        }

        if (_options.RetailWorldPacketCryptUseEmptyAad)
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt uses empty AAD (zero-length associated data).");
        }

        if (!string.Equals(
                _options.RetailWorldPacketCryptNonceLayout,
                WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultNonceLayout,
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt nonce layout override active ({NonceLayout}).",
                _options.RetailWorldPacketCryptNonceLayout);
        }

        if (!string.Equals(
                _options.RetailWorldPacketCryptServerNonceMagic,
                WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultServerNonceMagic,
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt server nonce magic override active ({ServerNonceMagic}).",
                _options.RetailWorldPacketCryptServerNonceMagic);
        }

        if (!string.Equals(
                _options.RetailWorldPacketCryptClientNonceMagic,
                WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultClientNonceMagic,
                StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "WorldProxy probe enabled: RetailWorldPacketCrypt client nonce magic override active ({ClientNonceMagic}).",
                _options.RetailWorldPacketCryptClientNonceMagic);
        }
    }

    private void LogStartupProbeFuzzerWarnings()
    {
        if (!_options.ProbeAuthResponseFuzzerEnabled)
        {
            return;
        }

        if (!_authResponseFuzzPlanRecognized)
        {
            _logger.LogWarning(
                "WorldProxy fuzzer enabled with unknown plan '{Plan}'. Mutation is disabled for this run.",
                _options.ProbeAuthResponseFuzzerPlan);
            return;
        }

        _logger.LogWarning(
            "WorldProxy fuzzer active: Plan={Plan}, Iteration={Iteration}, Mutation={Mutation}, LeadingZeroBits={LeadingZeroBits}, AccountDataPermutationVariant={AccountDataPermutationVariant}, OpcodeOverride={OpcodeOverride}, UseShortRealmId={UseShortRealmId}, SwapExpansionAndBillingFlags={SwapExpansionAndBillingFlags}, InsertPaddingU32AfterBitBlock={InsertPaddingU32AfterBitBlock}",
            _authResponseFuzzMutation.Plan,
            _authResponseFuzzMutation.Iteration,
            _authResponseFuzzMutation.MutationLabel,
            _authResponseFuzzMutation.LeadingZeroBits,
            _authResponseFuzzMutation.AccountDataPermutationVariant,
            _authResponseFuzzMutation.OpcodeOverride is uint fuzzOpcode
                ? $"0x{fuzzOpcode:X8}"
                : "<none>",
            _authResponseFuzzMutation.UseShortRealmId,
            _authResponseFuzzMutation.SwapExpansionAndBillingFlags,
            _authResponseFuzzMutation.InsertPaddingU32AfterBitBlock);
    }
}
