using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Adapter.WorldGateway;

internal static class AcoreAuthSessionBuilder
{
    public static byte[] BuildAcoreDigest(
        string accountName,
        ReadOnlySpan<byte> localChallenge4,
        uint authSeed,
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> sha1ZeroPrefix,
        int expectedDigestBytes)
    {
        byte[] accountBytes = Encoding.ASCII.GetBytes(accountName);
        byte[] authSeedBytes = BitConverter.GetBytes(authSeed);

        using var sha1 = SHA1.Create();
        sha1.TransformBlock(accountBytes, 0, accountBytes.Length, null, 0);

        byte[] prefix = sha1ZeroPrefix.ToArray();
        sha1.TransformBlock(prefix, 0, prefix.Length, null, 0);

        byte[] local = localChallenge4.ToArray();
        sha1.TransformBlock(local, 0, local.Length, null, 0);
        sha1.TransformBlock(authSeedBytes, 0, authSeedBytes.Length, null, 0);

        byte[] session = sessionKey.ToArray();
        sha1.TransformFinalBlock(session, 0, session.Length);

        byte[] digest = sha1.Hash ?? throw new InvalidOperationException("SHA1 produced null digest.");
        if (digest.Length != expectedDigestBytes)
        {
            throw new InvalidOperationException($"Unexpected SHA1 digest length: {digest.Length}.");
        }

        CryptographicOperations.ZeroMemory(prefix);
        CryptographicOperations.ZeroMemory(local);
        CryptographicOperations.ZeroMemory(session);
        return digest;
    }

    public static byte[] BuildMinimalAddonInfoBlob()
    {
        byte[] uncompressed = GC.AllocateUninitializedArray<byte>(8);
        BinaryPrimitives.WriteUInt32LittleEndian(uncompressed.AsSpan(0, 4), 0); // addonsCount
        BinaryPrimitives.WriteUInt32LittleEndian(uncompressed.AsSpan(4, 4), 0); // currentTime

        byte[] compressed;
        using (var output = new MemoryStream())
        {
            using (var zlib = new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            {
                zlib.Write(uncompressed, 0, uncompressed.Length);
            }

            compressed = output.ToArray();
        }

        byte[] addonInfo = GC.AllocateUninitializedArray<byte>(4 + compressed.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(addonInfo.AsSpan(0, 4), (uint)uncompressed.Length);
        compressed.AsSpan().CopyTo(addonInfo.AsSpan(4));
        return addonInfo;
    }

    public static byte[] BuildAcoreAuthSessionPayload(
        RetailAuthSessionFrame retailFrame,
        string accountName,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> addonInfo,
        uint acoreClientBuild,
        uint acoreRealmId)
    {
        byte[] accountBytes = Encoding.ASCII.GetBytes(accountName);

        int payloadBytes =
            4 + // build
            4 + // loginServerId
            accountBytes.Length + 1 + // account cstring
            4 + // loginServerType
            4 + // localChallenge(4)
            4 + // regionId
            4 + // battlegroupId
            4 + // realmId
            8 + // dosResponse
            digest.Length +
            addonInfo.Length;

        byte[] payload = GC.AllocateUninitializedArray<byte>(payloadBytes);
        Span<byte> span = payload;
        int offset = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), acoreClientBuild);
        offset += 4;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), 0); // LoginServerID
        offset += 4;

        accountBytes.CopyTo(span.Slice(offset, accountBytes.Length));
        offset += accountBytes.Length;
        span[offset++] = 0; // c-string terminator

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), 0); // LoginServerType
        offset += 4;

        retailFrame.LocalChallenge4.AsSpan().CopyTo(span.Slice(offset, 4));
        offset += 4;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), retailFrame.RegionId == 0 ? 1u : retailFrame.RegionId);
        offset += 4;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), retailFrame.BattlegroupId == 0 ? 1u : retailFrame.BattlegroupId);
        offset += 4;

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(offset, 4), acoreRealmId);
        offset += 4;

        BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(offset, 8), retailFrame.DosResponse);
        offset += 8;

        digest.CopyTo(span.Slice(offset, digest.Length));
        offset += digest.Length;

        addonInfo.CopyTo(span.Slice(offset, addonInfo.Length));
        offset += addonInfo.Length;

        if (offset != payloadBytes)
        {
            throw new InvalidOperationException($"Internal payload size mismatch. Written={offset}, Expected={payloadBytes}.");
        }

        return payload;
    }
}
