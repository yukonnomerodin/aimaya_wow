using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Adapter.WorldGateway;

/// <summary>
/// AzerothCore 3.3.5a world header crypt:
/// - key derivation via HMAC-SHA1(staticKey, sessionKey[40])
/// - ARC4-drop1024 stream ciphers
/// </summary>
internal sealed class AuthCrypt
{
    private static ReadOnlySpan<byte> ServerEncryptionKey =>
    [
        0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA,
        0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57
    ];

    private static ReadOnlySpan<byte> ServerDecryptionKey =>
    [
        0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5,
        0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE
    ];

    private readonly Arc4 _clientDecrypt = new();
    private readonly Arc4 _serverEncrypt = new();
    private readonly object _clientToServerLock = new();
    private readonly object _serverToClientLock = new();
    private bool _initialized;

    public bool IsInitialized => _initialized;

    public void Init(ReadOnlySpan<byte> sessionKey)
    {
        if (sessionKey.Length != 40)
        {
            throw new ArgumentException("AzerothCore session key must be 40 bytes.", nameof(sessionKey));
        }

        Span<byte> encDigest = stackalloc byte[20];
        Span<byte> decDigest = stackalloc byte[20];
        HMACSHA1.TryHashData(ServerEncryptionKey, sessionKey, encDigest, out int encWritten);
        HMACSHA1.TryHashData(ServerDecryptionKey, sessionKey, decDigest, out int decWritten);

        if (encWritten != 20 || decWritten != 20)
        {
            throw new InvalidOperationException("HMAC-SHA1 key derivation failed.");
        }

        _serverEncrypt.Init(encDigest);
        _clientDecrypt.Init(decDigest);

        Span<byte> drop = stackalloc byte[1024];
        _serverEncrypt.Transform(drop);
        _clientDecrypt.Transform(drop);

        CryptographicOperations.ZeroMemory(encDigest);
        CryptographicOperations.ZeroMemory(decDigest);
        CryptographicOperations.ZeroMemory(drop);

        _initialized = true;
    }

    /// <summary>
    /// Applies header crypto for packets traveling from Retail client to AzerothCore world.
    /// Must use the stream derived from ServerDecryptionKey because AC decrypts incoming client headers with it.
    /// </summary>
    public void TransformClientToServer(Span<byte> data)
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("AuthCrypt is not initialized.");
        }

        lock (_clientToServerLock)
        {
            _clientDecrypt.Transform(data);
        }
    }

    /// <summary>
    /// Applies header crypto for packets traveling from AzerothCore world to Retail client.
    /// Must use the stream derived from ServerEncryptionKey because AC encrypts outgoing headers with it.
    /// </summary>
    public void TransformServerToClient(Span<byte> data)
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("AuthCrypt is not initialized.");
        }

        lock (_serverToClientLock)
        {
            _serverEncrypt.Transform(data);
        }
    }

    // Backward-compatible aliases.
    public void DecryptRecv(Span<byte> data) => TransformClientToServer(data);

    public void EncryptSend(Span<byte> data) => TransformServerToClient(data);
}

internal sealed class AcoreClientHeaderEncryptor
{
    private const int HeaderBytes = 6;
    private const int MaxClientPacketSize = 10239; // AC check: size < 10240

    private readonly AuthCrypt _authCrypt;
    private readonly byte[] _header = new byte[HeaderBytes];
    private int _headerBytesRead;
    private int _payloadBytesRemaining;

    public AcoreClientHeaderEncryptor(AuthCrypt authCrypt)
    {
        _authCrypt = authCrypt ?? throw new ArgumentNullException(nameof(authCrypt));
    }

    public bool TryTransform(ReadOnlySequence<byte> input, IBufferWriter<byte> output, out long bytesWritten, out string? error)
    {
        bytesWritten = 0;
        error = null;

        foreach (ReadOnlyMemory<byte> segment in input)
        {
            ReadOnlySpan<byte> span = segment.Span;
            for (int idx = 0; idx < span.Length; idx++)
            {
                byte current = span[idx];

                if (_payloadBytesRemaining > 0)
                {
                    WriteByte(output, current);
                    bytesWritten++;
                    _payloadBytesRemaining--;
                    continue;
                }

                _header[_headerBytesRead++] = current;
                if (_headerBytesRead < HeaderBytes)
                {
                    continue;
                }

                ushort packetSize = BinaryPrimitives.ReadUInt16BigEndian(_header.AsSpan(0, 2));
                if (packetSize < 4 || packetSize > MaxClientPacketSize)
                {
                    error = $"Invalid AC client packet size in header: {packetSize}.";
                    return false;
                }

                _payloadBytesRemaining = packetSize - 4; // size includes opcode(4)

                _authCrypt.TransformClientToServer(_header);
                for (int i = 0; i < HeaderBytes; i++)
                {
                    WriteByte(output, _header[i]);
                }

                bytesWritten += HeaderBytes;
                _headerBytesRead = 0;
            }
        }

        return true;
    }

    private static void WriteByte(IBufferWriter<byte> output, byte value)
    {
        Span<byte> target = output.GetSpan(1);
        target[0] = value;
        output.Advance(1);
    }
}

internal sealed class AcoreServerHeaderDecryptor
{
    private const int MaxServerPacketSize = 16 * 1024 * 1024;

    private readonly AuthCrypt _authCrypt;
    private readonly Action<ushort, int>? _onFrameDecoded;
    private readonly byte[] _header = new byte[5];
    private int _headerBytesRead;
    private int _headerBytesExpected;
    private int _payloadBytesRemaining;

    public AcoreServerHeaderDecryptor(AuthCrypt authCrypt, Action<ushort, int>? onFrameDecoded = null)
    {
        _authCrypt = authCrypt ?? throw new ArgumentNullException(nameof(authCrypt));
        _onFrameDecoded = onFrameDecoded;
    }

    public bool TryTransform(ReadOnlySequence<byte> input, IBufferWriter<byte> output, out long bytesWritten, out string? error)
    {
        bytesWritten = 0;
        error = null;

        foreach (ReadOnlyMemory<byte> segment in input)
        {
            ReadOnlySpan<byte> span = segment.Span;
            for (int idx = 0; idx < span.Length; idx++)
            {
                byte current = span[idx];

                if (_payloadBytesRemaining > 0)
                {
                    WriteByte(output, current);
                    bytesWritten++;
                    _payloadBytesRemaining--;
                    continue;
                }

                _header[_headerBytesRead] = current;
                _authCrypt.TransformServerToClient(_header.AsSpan(_headerBytesRead, 1));
                _headerBytesRead++;

                if (_headerBytesRead == 1)
                {
                    _headerBytesExpected = (_header[0] & 0x80) != 0 ? 5 : 4;
                }

                if (_headerBytesRead < _headerBytesExpected)
                {
                    continue;
                }

                if (!TryDecodeServerPacketSize(_header.AsSpan(0, _headerBytesExpected), out int packetSizeIncludingOpcode, out string decodeError))
                {
                    error = decodeError;
                    return false;
                }

                int payloadBytes = packetSizeIncludingOpcode - 2; // size includes opcode(2)
                if (payloadBytes < 0 || payloadBytes > MaxServerPacketSize)
                {
                    error = $"Invalid AC server payload size in header: {payloadBytes}.";
                    return false;
                }

                ushort opcode = _headerBytesExpected == 4
                    ? BinaryPrimitives.ReadUInt16LittleEndian(_header.AsSpan(2, 2))
                    : BinaryPrimitives.ReadUInt16LittleEndian(_header.AsSpan(3, 2));
                _onFrameDecoded?.Invoke(opcode, payloadBytes);

                _payloadBytesRemaining = payloadBytes;
                for (int i = 0; i < _headerBytesExpected; i++)
                {
                    WriteByte(output, _header[i]);
                }

                bytesWritten += _headerBytesExpected;
                _headerBytesRead = 0;
                _headerBytesExpected = 0;
            }
        }

        return true;
    }

    private static bool TryDecodeServerPacketSize(ReadOnlySpan<byte> header, out int packetSizeIncludingOpcode, out string error)
    {
        packetSizeIncludingOpcode = 0;
        error = string.Empty;

        if (header.Length == 4)
        {
            packetSizeIncludingOpcode = ((header[0] & 0x7F) << 8) | header[1];
        }
        else if (header.Length == 5)
        {
            packetSizeIncludingOpcode = ((header[0] & 0x7F) << 16) | (header[1] << 8) | header[2];
        }
        else
        {
            error = $"Unsupported AC server header length: {header.Length}.";
            return false;
        }

        if (packetSizeIncludingOpcode < 2)
        {
            error = $"Invalid AC server packet size field: {packetSizeIncludingOpcode}.";
            return false;
        }

        return true;
    }

    private static void WriteByte(IBufferWriter<byte> output, byte value)
    {
        Span<byte> target = output.GetSpan(1);
        target[0] = value;
        output.Advance(1);
    }
}

internal readonly record struct AcoreAuthSessionBridgeResult(
    byte[] Frame,
    AuthCrypt HeaderCrypt,
    byte[] SessionKey,
    byte[]? BnetKeyData64,
    int AccountId,
    string AccountIdSource);

internal sealed class Arc4
{
    private readonly byte[] _state = new byte[256];
    private int _i;
    private int _j;
    private bool _initialized;

    public void Init(ReadOnlySpan<byte> key)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("ARC4 key cannot be empty.", nameof(key));
        }

        for (int idx = 0; idx < 256; idx++)
        {
            _state[idx] = (byte)idx;
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + _state[i] + key[i % key.Length]) & 0xFF;
            (_state[i], _state[j]) = (_state[j], _state[i]);
        }

        _i = 0;
        _j = 0;
        _initialized = true;
    }

    public void Transform(Span<byte> data)
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("ARC4 is not initialized.");
        }

        for (int n = 0; n < data.Length; n++)
        {
            _i = (_i + 1) & 0xFF;
            _j = (_j + _state[_i]) & 0xFF;
            (_state[_i], _state[_j]) = (_state[_j], _state[_i]);
            int k = _state[(_state[_i] + _state[_j]) & 0xFF];
            data[n] = (byte)(data[n] ^ k);
        }
    }
}
