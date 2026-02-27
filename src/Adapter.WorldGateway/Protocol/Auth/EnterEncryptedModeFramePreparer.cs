namespace Adapter.WorldGateway;

internal static class EnterEncryptedModeFramePreparer
{
    public static bool TryPrepareRetailEnterEncryptedModeFrame(
        WorldProxyOptions options,
        ReadOnlySpan<byte> sessionKey40,
        ReadOnlySpan<byte> bnetKeyData64,
        ReadOnlySpan<byte> localChallenge32,
        ReadOnlySpan<byte> serverChallenge32,
        uint defaultRetailOpcode,
        out byte[] retailFrame,
        out uint retailOpcode,
        out string? error,
        out string keySource,
        out string wireFormat,
        out byte[] retailWorldEncryptKey32,
        out EnterEncryptedModeProof proof)
    {
        retailFrame = Array.Empty<byte>();
        retailOpcode = defaultRetailOpcode;
        error = null;
        keySource = "legacy-session_key";
        wireFormat = options.EnterEncryptedModeSignatureFirst ? "SignatureRegionBit" : "RegionSignatureBit";
        retailWorldEncryptKey32 = Array.Empty<byte>();
        proof = default;

        if (options.EnterEncryptedModeUseGoldenPayload)
        {
            if (EnterEncryptedModeGoldenMetadataLoader.TryBuildRetailEnterEncryptedModeFrameFromGoldenMetadata(
                    options.EnterEncryptedModeGoldenMetadataPath,
                    defaultRetailOpcode,
                    out retailFrame,
                    out retailOpcode,
                    out error,
                    out retailWorldEncryptKey32,
                    out proof))
            {
                // Golden metadata contains payload/opcode, but typically has no runtime world-crypt key.
                // Re-derive encryption key from current session lineage to keep post-ACK crypto active.
                if (EnterEncryptedModeFrameBuilder.TryBuildRetailEnterEncryptedModeFrame(
                        sessionKey40,
                        bnetKeyData64,
                        localChallenge32,
                        serverChallenge32,
                        defaultRetailOpcode,
                        options.EnterEncryptedModeSignatureFirst,
                        options.EnterEncryptedModeRegionGroup,
                        options.EnterEncryptedModeIncludeRegionGroup,
                        options.EnterEncryptedModeEnabled,
                        options.EnterEncryptedModeEnabledAsByte,
                        options.EnterEncryptedModePreferBnetKeyData,
                        options.ExposeRetailWorldEncryptKeyInProof,
                        out _,
                        out _,
                        out string runtimeKeySource,
                        out _,
                        out byte[] runtimeRetailWorldEncryptKey32,
                        out EnterEncryptedModeProof runtimeProof))
                {
                    if (runtimeRetailWorldEncryptKey32.Length == 32)
                    {
                        retailWorldEncryptKey32 = runtimeRetailWorldEncryptKey32;
                        keySource = $"golden-payload+{runtimeKeySource}";
                        proof = proof with
                        {
                            PreferBnetKeyData = runtimeProof.PreferBnetKeyData,
                            KeySource = $"{proof.KeySource};crypto:{runtimeKeySource}",
                            SessionKeySha256 = runtimeProof.SessionKeySha256,
                            BnetKeyDataSha256 = runtimeProof.BnetKeyDataSha256,
                            BnetKeyDerivationError = runtimeProof.BnetKeyDerivationError,
                            RetailWorldEncryptKeySha256 = runtimeProof.RetailWorldEncryptKeySha256,
                            RetailWorldEncryptKeyHex = runtimeProof.RetailWorldEncryptKeyHex,
                            LocalChallengeHex = runtimeProof.LocalChallengeHex,
                            ServerChallengeHex = runtimeProof.ServerChallengeHex
                        };

                        if (options.EnterEncryptedModeGoldenPatchRuntimeSignature)
                        {
                            if (!EnterEncryptedModeFrameHelpers.TryPatchSignatureInFrame(
                                    retailFrame,
                                    runtimeProof.SignatureHex,
                                    options.EnterEncryptedModeIncludeRegionGroup,
                                    options.EnterEncryptedModeSignatureFirst,
                                    out string? patchError))
                            {
                                error = patchError;
                                return false;
                            }

                            if (!EnterEncryptedModeFrameHelpers.TryExtractPayloadFromFrame(retailFrame, out byte[] patchedPayload, out string? payloadError))
                            {
                                error = payloadError;
                                return false;
                            }

                            keySource = $"golden-payload+{runtimeKeySource}+sig-patch";
                            wireFormat = "GoldenReplay+RuntimeSignaturePatch";
                            proof = proof with
                            {
                                RegionGroup = options.EnterEncryptedModeRegionGroup,
                                IncludeRegionGroup = options.EnterEncryptedModeIncludeRegionGroup,
                                Enabled = options.EnterEncryptedModeEnabled,
                                EnabledAsByte = options.EnterEncryptedModeEnabledAsByte,
                                SignatureFirst = options.EnterEncryptedModeSignatureFirst,
                                KeySource = $"{proof.KeySource};crypto:{runtimeKeySource};signature:runtime",
                                WireFormat = wireFormat,
                                ToSignHex = runtimeProof.ToSignHex,
                                SignatureHex = runtimeProof.SignatureHex,
                                PayloadHex = Convert.ToHexString(patchedPayload),
                                PayloadBytes = patchedPayload.Length
                            };
                        }
                    }
                    else
                    {
                        keySource = "golden-metadata";
                        proof = proof with { BnetKeyDerivationError = runtimeProof.BnetKeyDerivationError };
                    }
                }
                else
                {
                    keySource = "golden-metadata";
                }

                if (wireFormat != "GoldenReplay+RuntimeSignaturePatch")
                {
                    wireFormat = "GoldenReplay";
                }
                return true;
            }

            return false;
        }

        return EnterEncryptedModeFrameBuilder.TryBuildRetailEnterEncryptedModeFrame(
            sessionKey40,
            bnetKeyData64,
            localChallenge32,
            serverChallenge32,
            defaultRetailOpcode,
            options.EnterEncryptedModeSignatureFirst,
            options.EnterEncryptedModeRegionGroup,
            options.EnterEncryptedModeIncludeRegionGroup,
            options.EnterEncryptedModeEnabled,
            options.EnterEncryptedModeEnabledAsByte,
            options.EnterEncryptedModePreferBnetKeyData,
            options.ExposeRetailWorldEncryptKeyInProof,
            out retailFrame,
            out error,
            out keySource,
            out wireFormat,
            out retailWorldEncryptKey32,
            out proof);
    }
}
