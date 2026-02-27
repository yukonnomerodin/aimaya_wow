using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Adapter.WorldGateway;

internal static class EnterEncryptedModeFrameBuilder
{
    private static readonly byte[] TrinityEncryptionKeySeed =
    [
        0x71, 0xC9, 0xED, 0x5A, 0xA7, 0x0E, 0x4D, 0xFF, 0x4C, 0x36, 0xA6, 0x5A, 0x3E, 0x46, 0x8A, 0x4A,
        0x5D, 0xA1, 0x48, 0xC8, 0x30, 0x47, 0x4A, 0xDE, 0xF6, 0x0D, 0x6C, 0xBE, 0x6F, 0xE4, 0x55, 0x73
    ];

    private static readonly byte[] TrinitySessionKeySeed =
    [
        0xE8, 0x1E, 0x8B, 0x59, 0x27, 0x62, 0x1E, 0xAA, 0x86, 0x15, 0x18, 0xEA, 0xC0, 0xBF, 0x66, 0x8C,
        0x6D, 0xBF, 0x83, 0x93, 0xBC, 0xAA, 0x80, 0x52, 0x5B, 0x1E, 0xDC, 0x23, 0xA0, 0x12, 0xB7, 0x50
    ];

    private static readonly byte[] TrinityEnterEncryptedModePrivateKey =
    [
        0x08, 0xBD, 0xC7, 0xA3, 0xCC, 0xC3, 0x4F, 0x3F,
        0x6A, 0x0B, 0xFF, 0xCF, 0x31, 0xC1, 0xB6, 0x97,
        0x69, 0x1E, 0x72, 0x9A, 0x0A, 0xAB, 0x2C, 0x77,
        0xC3, 0x6F, 0x8A, 0xE7, 0x5A, 0x9A, 0xA7, 0xC9
    ];

    private static readonly byte[] TrinityEnableEncryptionSeed =
    [
        0x66, 0xBE, 0x29, 0x79, 0xEF, 0xF2, 0xD5, 0xB5, 0x61, 0x53, 0xF6, 0x5F, 0x45, 0xAE, 0x81, 0xCB,
        0x32, 0xEC, 0x94, 0xEC, 0x75, 0xB3, 0x5F, 0x44, 0x6A, 0x63, 0x43, 0x67, 0x17, 0x20, 0x44, 0x34
    ];

    private static readonly byte[] TrinityEnableEncryptionContext =
    [
        0xA7, 0x1F, 0xB6, 0x9B, 0xC9, 0x7C, 0xDD, 0x96,
        0xE9, 0xBB, 0xB8, 0x21, 0x39, 0x8D, 0x5A, 0xD4
    ];

    public static bool TryBuildRetailEnterEncryptedModeFrame(
        ReadOnlySpan<byte> sessionKey40,
        ReadOnlySpan<byte> bnetKeyData64,
        ReadOnlySpan<byte> localChallenge32,
        ReadOnlySpan<byte> serverChallenge32,
        uint retailOpcode,
        bool signatureFirst,
        int regionGroup,
        bool includeRegionGroup,
        bool enabled,
        bool enabledAsByte,
        bool preferBnetKeyData,
        bool exposeRetailWorldEncryptKeyInProof,
        out byte[] retailFrame,
        out string? error,
        out string keySource,
        out string wireFormat,
        out byte[] retailWorldEncryptKey32,
        out EnterEncryptedModeProof proof)
    {
        retailFrame = Array.Empty<byte>();
        error = null;
        keySource = "legacy-session_key";
        wireFormat = signatureFirst ? "SignatureRegionBit" : "RegionSignatureBit";
        retailWorldEncryptKey32 = Array.Empty<byte>();
        proof = default;

        if (sessionKey40.Length != WorldGatewayProtocolConstants.AcoreSessionKeyBytes)
        {
            error =
                $"Invalid session key length {sessionKey40.Length}. Expected {WorldGatewayProtocolConstants.AcoreSessionKeyBytes}.";
            return false;
        }

        if (localChallenge32.Length != 32 || serverChallenge32.Length != 32)
        {
            error = $"Invalid challenge lengths. Local={localChallenge32.Length}, Server={serverChallenge32.Length}.";
            return false;
        }

        try
        {
            byte[] encryptionKey32 = Array.Empty<byte>();
            string? bnetKeyDerivationError = null;
            if (preferBnetKeyData && bnetKeyData64.Length == 64)
            {
                if (!TryBuildTrinityEncryptKeyFromBnetKeyData(
                        bnetKeyData64,
                        localChallenge32,
                        serverChallenge32,
                        out encryptionKey32,
                        out bnetKeyDerivationError))
                {
                    // Fallback to legacy key derivation to keep handshake lab surface broad.
                    keySource = "legacy-session_key_fallback_bnet_invalid";
                }
                else
                {
                    keySource = "session_key_bnet";
                }
            }

            if (encryptionKey32.Length == 0)
            {
                using var encryptKeyGen = new HMACSHA512(sessionKey40.ToArray());
                encryptKeyGen.TransformBlock(localChallenge32.ToArray(), 0, localChallenge32.Length, null, 0);
                encryptKeyGen.TransformBlock(serverChallenge32.ToArray(), 0, serverChallenge32.Length, null, 0);
                encryptKeyGen.TransformFinalBlock(TrinityEncryptionKeySeed, 0, TrinityEncryptionKeySeed.Length);
                encryptionKey32 = encryptKeyGen.Hash![..32];

                if (preferBnetKeyData && bnetKeyData64.Length != 64)
                {
                    keySource = "legacy-session_key_fallback_bnet_missing";
                }
                else if (!preferBnetKeyData)
                {
                    keySource = "legacy-session_key_forced";
                }
            }

            byte[] toSign;
            using (var signDigest = new HMACSHA512(encryptionKey32))
            {
                byte[] enabledFlag = [enabled ? (byte)1 : (byte)0];
                signDigest.TransformBlock(enabledFlag, 0, enabledFlag.Length, null, 0);
                signDigest.TransformFinalBlock(TrinityEnableEncryptionSeed, 0, TrinityEnableEncryptionSeed.Length);
                toSign = signDigest.Hash!;
            }

            byte[] signature;
            {
                var signer = new Ed25519ctxSigner(TrinityEnableEncryptionContext);
                signer.Init(true, new Ed25519PrivateKeyParameters(TrinityEnterEncryptedModePrivateKey, 0));
                signer.BlockUpdate(toSign, 0, toSign.Length);
                signature = signer.GenerateSignature();
            }

            if (signature.Length != 64)
            {
                error = $"Invalid Ed25519 signature length: {signature.Length}.";
                return false;
            }

            var payload = new BitPackedBufferWriter(initialCapacity: 80);
            if (includeRegionGroup)
            {
                if (signatureFirst)
                {
                    for (int i = 0; i < signature.Length; i++)
                    {
                        payload.WriteByte(signature[i]);
                    }

                    payload.WriteInt32LE(regionGroup);
                }
                else
                {
                    payload.WriteInt32LE(regionGroup);
                    for (int i = 0; i < signature.Length; i++)
                    {
                        payload.WriteByte(signature[i]);
                    }
                }
            }
            else
            {
                for (int i = 0; i < signature.Length; i++)
                {
                    payload.WriteByte(signature[i]);
                }
            }

            if (enabledAsByte)
            {
                payload.WriteByte(enabled ? (byte)1 : (byte)0);
            }
            else
            {
                payload.WriteBit(enabled);
                payload.FlushBits();
            }

            retailFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(retailOpcode, payload.WrittenSpan);
            retailWorldEncryptKey32 = encryptionKey32.ToArray();
            proof = new EnterEncryptedModeProof(
                TimestampUtc: DateTimeOffset.UtcNow.ToString("O"),
                RetailOpcode: retailOpcode,
                RegionGroup: regionGroup,
                IncludeRegionGroup: includeRegionGroup,
                Enabled: enabled,
                EnabledAsByte: enabledAsByte,
                SignatureFirst: signatureFirst,
                PreferBnetKeyData: preferBnetKeyData,
                KeySource: keySource,
                WireFormat: wireFormat,
                SessionKeySha256: Convert.ToHexString(SHA256.HashData(sessionKey40)),
                BnetKeyDataSha256: bnetKeyData64.Length == 64 ? Convert.ToHexString(SHA256.HashData(bnetKeyData64)) : null,
                BnetKeyDerivationError: bnetKeyDerivationError,
                RetailWorldEncryptKeySha256: Convert.ToHexString(SHA256.HashData(encryptionKey32)),
                RetailWorldEncryptKeyHex: exposeRetailWorldEncryptKeyInProof ? Convert.ToHexString(encryptionKey32) : null,
                LocalChallengeHex: Convert.ToHexString(localChallenge32),
                ServerChallengeHex: Convert.ToHexString(serverChallenge32),
                ToSignHex: Convert.ToHexString(toSign),
                SignatureHex: Convert.ToHexString(signature),
                PayloadHex: Convert.ToHexString(payload.WrittenSpan),
                PayloadBytes: payload.WrittenSpan.Length);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or ArgumentException)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryBuildTrinityEncryptKeyFromBnetKeyData(
        ReadOnlySpan<byte> bnetKeyData64,
        ReadOnlySpan<byte> localChallenge32,
        ReadOnlySpan<byte> serverChallenge32,
        out byte[] encryptKey32,
        out string? error)
    {
        encryptKey32 = Array.Empty<byte>();
        error = null;

        if (bnetKeyData64.Length != 64)
        {
            error = $"Invalid bnet key_data length {bnetKeyData64.Length}. Expected 64.";
            return false;
        }

        try
        {
            byte[] keyDataHash = SHA512.HashData(bnetKeyData64);
            byte[] sessionSeed;
            using (var sessionHmac = new HMACSHA512(keyDataHash))
            {
                sessionHmac.TransformBlock(serverChallenge32.ToArray(), 0, serverChallenge32.Length, null, 0);
                sessionHmac.TransformBlock(localChallenge32.ToArray(), 0, localChallenge32.Length, null, 0);
                sessionHmac.TransformFinalBlock(TrinitySessionKeySeed, 0, TrinitySessionKeySeed.Length);
                sessionSeed = sessionHmac.Hash!;
            }

            byte[] sessionKey40 = GenerateSessionKey40(sessionSeed);
            using var encryptKeyGen = new HMACSHA512(sessionKey40);
            encryptKeyGen.TransformBlock(localChallenge32.ToArray(), 0, localChallenge32.Length, null, 0);
            encryptKeyGen.TransformBlock(serverChallenge32.ToArray(), 0, serverChallenge32.Length, null, 0);
            encryptKeyGen.TransformFinalBlock(TrinityEncryptionKeySeed, 0, TrinityEncryptionKeySeed.Length);
            encryptKey32 = encryptKeyGen.Hash![..32];
            CryptographicOperations.ZeroMemory(keyDataHash);
            CryptographicOperations.ZeroMemory(sessionSeed);
            CryptographicOperations.ZeroMemory(sessionKey40);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or ArgumentException)
        {
            error = ex.Message;
            return false;
        }
    }

    private static byte[] GenerateSessionKey40(ReadOnlySpan<byte> seedDigest)
    {
        if (seedDigest.Length == 0)
        {
            throw new InvalidOperationException("Session key seed digest is empty.");
        }

        int half = seedDigest.Length / 2;
        byte[] firstHalf = seedDigest[..half].ToArray();
        byte[] secondHalf = seedDigest[half..].ToArray();

        byte[] o1 = SHA512.HashData(firstHalf);
        byte[] o2 = SHA512.HashData(secondHalf);
        byte[] o0 = SHA512.HashData(Concat(o1, new byte[64], o2));

        byte[] outKey = new byte[40];
        int offset = 0;
        int o0Index = 0;
        while (offset < outKey.Length)
        {
            if (o0Index >= o0.Length)
            {
                o0 = SHA512.HashData(Concat(o1, o0, o2));
                o0Index = 0;
            }

            outKey[offset++] = o0[o0Index++];
        }

        CryptographicOperations.ZeroMemory(firstHalf);
        CryptographicOperations.ZeroMemory(secondHalf);
        CryptographicOperations.ZeroMemory(o0);
        CryptographicOperations.ZeroMemory(o1);
        CryptographicOperations.ZeroMemory(o2);
        return outKey;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        byte[] result = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(result.AsSpan(0, a.Length));
        b.CopyTo(result.AsSpan(a.Length, b.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length, c.Length));
        return result;
    }
}
