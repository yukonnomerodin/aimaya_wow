using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Adapter.AuthGateway;

public interface ISrp6Calculator
{
    ReadOnlyMemory<byte> Generator { get; }
    ReadOnlyMemory<byte> Modulus { get; }

    Srp6ServerChallenge CreateServerChallenge(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> verifier);

    bool TryVerifyClientProof(
        string username,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> verifier,
        ReadOnlySpan<byte> serverPrivateb,
        ReadOnlySpan<byte> serverPublicB,
        ReadOnlySpan<byte> clientPublicA,
        ReadOnlySpan<byte> clientProofM1,
        out Srp6ProofResult result);
}

public readonly record struct Srp6ServerChallenge(
    byte[] ServerPublicB,
    byte[] ServerPrivateb,
    byte[] Salt);

public readonly record struct Srp6ProofResult(
    byte[] SessionKey,
    byte[] ServerProofM2);

/// <summary>
/// SRP6 bridge implementation aligned with AzerothCore 3.3.5a:
/// - g = 7
/// - N = 0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7 (wire as little-endian bytes)
/// - B = (g^b + 3*v) mod N
/// - u = SHA1(A || B)
/// - S = (A * v^u)^b mod N
/// - K = SHA1Interleave(S)
/// - M1 = SHA1(H(N) xor H(g), H(I), s, A, B, K)
/// - M2 = SHA1(A, M1, K)
/// </summary>
public sealed class Srp6Calculator : ISrp6Calculator
{
    public const int SaltLength = 32;
    public const int VerifierLength = 32;
    public const int EphemeralKeyLength = 32;
    public const int ProofLength = 20;
    public const int SessionKeyLength = 40;

    private const string ModulusHex = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7";

    private static readonly byte[] GeneratorBytes = { 0x07 };
    private static readonly byte[] ModulusBytes = BuildLittleEndianModulus(ModulusHex);
    private static readonly BigInteger GeneratorInt = new(GeneratorBytes, isUnsigned: true, isBigEndian: false);
    private static readonly BigInteger ModulusInt = new(ModulusBytes, isUnsigned: true, isBigEndian: false);
    private static readonly BigInteger Three = new(3);
    private static readonly byte[] NgHash = BuildNgHash();

    public ReadOnlyMemory<byte> Generator => GeneratorBytes;
    public ReadOnlyMemory<byte> Modulus => ModulusBytes;

    public Srp6ServerChallenge CreateServerChallenge(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> verifier)
    {
        ValidateFixedLength(salt, SaltLength, nameof(salt));
        ValidateFixedLength(verifier, VerifierLength, nameof(verifier));

        byte[] privateb = RandomNumberGenerator.GetBytes(EphemeralKeyLength);
        BigInteger b = new(privateb, isUnsigned: true, isBigEndian: false);
        BigInteger v = new(verifier, isUnsigned: true, isBigEndian: false);

        BigInteger publicB = (BigInteger.ModPow(GeneratorInt, b, ModulusInt) + (v * Three)) % ModulusInt;
        if (publicB.Sign < 0)
        {
            publicB += ModulusInt;
        }

        return new Srp6ServerChallenge(
            ServerPublicB: ToFixedLittleEndian(publicB, EphemeralKeyLength),
            ServerPrivateb: privateb,
            Salt: salt.ToArray());
    }

    public bool TryVerifyClientProof(
        string username,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> verifier,
        ReadOnlySpan<byte> serverPrivateb,
        ReadOnlySpan<byte> serverPublicB,
        ReadOnlySpan<byte> clientPublicA,
        ReadOnlySpan<byte> clientProofM1,
        out Srp6ProofResult result)
    {
        if (string.IsNullOrWhiteSpace(username) ||
            salt.Length != SaltLength ||
            verifier.Length != VerifierLength ||
            serverPrivateb.Length != EphemeralKeyLength ||
            serverPublicB.Length != EphemeralKeyLength ||
            clientPublicA.Length != EphemeralKeyLength ||
            clientProofM1.Length != ProofLength)
        {
            result = default;
            return false;
        }

        // BigInteger heavy work is isolated in this method to keep the hot path explicit.
        BigInteger A = new(clientPublicA, isUnsigned: true, isBigEndian: false);
        if ((A % ModulusInt).IsZero)
        {
            result = default;
            return false;
        }

        BigInteger v = new(verifier, isUnsigned: true, isBigEndian: false);
        BigInteger b = new(serverPrivateb, isUnsigned: true, isBigEndian: false);

        byte[] uDigest = Sha1Concat(clientPublicA, serverPublicB);
        BigInteger u = new(uDigest, isUnsigned: true, isBigEndian: false);

        BigInteger sharedSecret = BigInteger.ModPow(
            (A * BigInteger.ModPow(v, u, ModulusInt)) % ModulusInt,
            b,
            ModulusInt);

        byte[] s = ToFixedLittleEndian(sharedSecret, EphemeralKeyLength);
        byte[] sessionKey = Sha1Interleave(s);

        byte[] iHash = SHA1.HashData(Encoding.UTF8.GetBytes(username.ToUpperInvariant()));
        byte[] ourM1 = ComputeClientProof(iHash, salt, clientPublicA, serverPublicB, sessionKey);

        if (!CryptographicOperations.FixedTimeEquals(ourM1, clientProofM1))
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            result = default;
            return false;
        }

        byte[] serverM2 = ComputeServerProof(clientPublicA, clientProofM1, sessionKey);
        result = new Srp6ProofResult(sessionKey, serverM2);
        return true;
    }

    private static byte[] ComputeClientProof(
        ReadOnlySpan<byte> iHash,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> clientPublicA,
        ReadOnlySpan<byte> serverPublicB,
        ReadOnlySpan<byte> sessionKey)
    {
        Span<byte> input = stackalloc byte[20 + 20 + SaltLength + EphemeralKeyLength + EphemeralKeyLength + SessionKeyLength];
        int offset = 0;

        NgHash.CopyTo(input[offset..]);
        offset += 20;
        iHash.CopyTo(input[offset..]);
        offset += 20;
        salt.CopyTo(input[offset..]);
        offset += SaltLength;
        clientPublicA.CopyTo(input[offset..]);
        offset += EphemeralKeyLength;
        serverPublicB.CopyTo(input[offset..]);
        offset += EphemeralKeyLength;
        sessionKey.CopyTo(input[offset..]);

        return SHA1.HashData(input);
    }

    private static byte[] ComputeServerProof(
        ReadOnlySpan<byte> clientPublicA,
        ReadOnlySpan<byte> clientProofM1,
        ReadOnlySpan<byte> sessionKey)
    {
        Span<byte> input = stackalloc byte[EphemeralKeyLength + ProofLength + SessionKeyLength];
        int offset = 0;

        clientPublicA.CopyTo(input[offset..]);
        offset += EphemeralKeyLength;
        clientProofM1.CopyTo(input[offset..]);
        offset += ProofLength;
        sessionKey.CopyTo(input[offset..]);

        return SHA1.HashData(input);
    }

    private static byte[] Sha1Interleave(ReadOnlySpan<byte> secret)
    {
        Span<byte> even = stackalloc byte[EphemeralKeyLength / 2];
        Span<byte> odd = stackalloc byte[EphemeralKeyLength / 2];

        for (int i = 0; i < EphemeralKeyLength / 2; i++)
        {
            even[i] = secret[(2 * i) + 0];
            odd[i] = secret[(2 * i) + 1];
        }

        int p = 0;
        while (p < secret.Length && secret[p] == 0)
        {
            p++;
        }

        if ((p & 1) != 0)
        {
            p++;
        }

        p /= 2;

        byte[] h0 = SHA1.HashData(even[p..]);
        byte[] h1 = SHA1.HashData(odd[p..]);

        byte[] key = new byte[SessionKeyLength];
        for (int i = 0; i < ProofLength; i++)
        {
            key[(2 * i) + 0] = h0[i];
            key[(2 * i) + 1] = h1[i];
        }

        return key;
    }

    private static byte[] BuildNgHash()
    {
        byte[] nHash = SHA1.HashData(ModulusBytes);
        byte[] gHash = SHA1.HashData(GeneratorBytes);
        byte[] ng = new byte[ProofLength];

        for (int i = 0; i < ProofLength; i++)
        {
            ng[i] = (byte)(nHash[i] ^ gHash[i]);
        }

        return ng;
    }

    private static byte[] Sha1Concat(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        byte[] buffer = new byte[left.Length + right.Length];
        left.CopyTo(buffer);
        right.CopyTo(buffer.AsSpan(left.Length));
        return SHA1.HashData(buffer);
    }

    private static byte[] BuildLittleEndianModulus(string hex)
    {
        byte[] bytes = Convert.FromHexString(hex);
        Array.Reverse(bytes);
        return bytes;
    }

    private static byte[] ToFixedLittleEndian(BigInteger value, int length)
    {
        byte[] buffer = new byte[length];
        if (!value.TryWriteBytes(buffer, out int written, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException("Failed to encode SRP6 value.");
        }

        if (written > length)
        {
            throw new InvalidOperationException("SRP6 value exceeded expected key length.");
        }

        return buffer;
    }

    private static void ValidateFixedLength(ReadOnlySpan<byte> value, int expectedLength, string paramName)
    {
        if (value.Length != expectedLength)
        {
            throw new ArgumentException($"'{paramName}' must be {expectedLength} bytes.", paramName);
        }
    }
}
