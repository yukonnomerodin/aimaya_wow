using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Adapter.WorldGateway;

internal sealed class RetailWorldPacketCrypt
{
    private const int HeaderBytes = 16;
    private const int MinFrameBytes = 20;
    private const int TagBytes = 12;
    private const int MaxFrameBytes = 16 * 1024 * 1024;

    private readonly AesGcm _clientDecrypt;
    private readonly AesGcm _serverEncrypt;
    private readonly bool _useSizeAsAad;
    private readonly bool _useEmptyAad;
    private readonly int _aadSizeBytes;
    private readonly RetailWorldPacketCryptNonceLayout _nonceLayout;
    private readonly uint _clientNonceMagic;
    private readonly uint _serverNonceMagic;
    private ulong _clientCounter;
    private ulong _serverCounter;

    public RetailWorldPacketCrypt(
        ReadOnlySpan<byte> key32,
        ulong serverInitialCounter = 0,
        ulong clientInitialCounter = 0,
        bool useSizeAsAad = false,
        int aadSizeBytes = 4,
        bool useEmptyAad = false,
        string nonceLayout = WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultNonceLayout,
        string serverNonceMagic = WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultServerNonceMagic,
        string clientNonceMagic = WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultClientNonceMagic)
    {
        if (key32.Length != 32)
        {
            throw new ArgumentException("Retail world crypt key must be exactly 32 bytes.", nameof(key32));
        }

        if (aadSizeBytes != 2 && aadSizeBytes != 4)
        {
            throw new ArgumentOutOfRangeException(nameof(aadSizeBytes), aadSizeBytes, "Retail world crypt AAD size must be 2 or 4 bytes.");
        }

        _clientDecrypt = new AesGcm(key32, TagBytes);
        _serverEncrypt = new AesGcm(key32, TagBytes);
        _useSizeAsAad = useSizeAsAad;
        _useEmptyAad = useEmptyAad;
        _aadSizeBytes = aadSizeBytes;
        _nonceLayout = ParseNonceLayout(nonceLayout);
        _clientNonceMagic = ParseClientNonceMagic(clientNonceMagic);
        _serverNonceMagic = ParseServerNonceMagic(serverNonceMagic);
        _clientCounter = clientInitialCounter;
        _serverCounter = serverInitialCounter;
    }

    public bool TryEncryptServerFrame(ReadOnlySpan<byte> plainFrame, out byte[] encryptedFrame, out string? error)
    {
        encryptedFrame = Array.Empty<byte>();
        error = null;

        if (!TryValidateRetailFrame(plainFrame, out int bodyLength, out int frameBytes, out error))
        {
            return false;
        }

        encryptedFrame = GC.AllocateUninitializedArray<byte>(frameBytes);
        Span<byte> destination = encryptedFrame;

        // Size stays plaintext; optional probe mode may include size as AAD.
        plainFrame.Slice(0, 4).CopyTo(destination.Slice(0, 4));
        Span<byte> tag = destination.Slice(4, TagBytes);
        Span<byte> ciphertext = destination.Slice(HeaderBytes, bodyLength);
        ReadOnlySpan<byte> associatedData = (_useEmptyAad || !_useSizeAsAad)
            ? ReadOnlySpan<byte>.Empty
            : plainFrame.Slice(0, _aadSizeBytes);

        Span<byte> nonce = stackalloc byte[12];
        WriteNonce(_serverCounter, _serverNonceMagic, nonce, _nonceLayout);

        try
        {
            _serverEncrypt.Encrypt(
                nonce,
                plainFrame.Slice(HeaderBytes, bodyLength),
                ciphertext,
                tag,
                associatedData);
        }
        catch (CryptographicException ex)
        {
            encryptedFrame = Array.Empty<byte>();
            error = ex.Message;
            return false;
        }

        _serverCounter++;
        return true;
    }

    public bool TryDecryptClientFrame(ReadOnlySpan<byte> encryptedFrame, out byte[] plainFrame, out string? error)
    {
        plainFrame = Array.Empty<byte>();
        error = null;

        if (!TryValidateRetailFrame(encryptedFrame, out int bodyLength, out int frameBytes, out error))
        {
            return false;
        }

        plainFrame = GC.AllocateUninitializedArray<byte>(frameBytes);
        Span<byte> destination = plainFrame;

        encryptedFrame.Slice(0, 4).CopyTo(destination.Slice(0, 4));
        destination.Slice(4, TagBytes).Clear();
        ReadOnlySpan<byte> associatedData = (_useEmptyAad || !_useSizeAsAad)
            ? ReadOnlySpan<byte>.Empty
            : encryptedFrame.Slice(0, _aadSizeBytes);

        Span<byte> nonce = stackalloc byte[12];
        WriteNonce(_clientCounter, _clientNonceMagic, nonce, _nonceLayout);

        try
        {
            _clientDecrypt.Decrypt(
                nonce,
                encryptedFrame.Slice(HeaderBytes, bodyLength),
                encryptedFrame.Slice(4, TagBytes),
                destination.Slice(HeaderBytes, bodyLength),
                associatedData);
        }
        catch (CryptographicException ex)
        {
            plainFrame = Array.Empty<byte>();
            error = ex.Message;
            return false;
        }

        _clientCounter++;
        return true;
    }

    private static bool TryValidateRetailFrame(ReadOnlySpan<byte> frame, out int bodyLength, out int frameBytes, out string? error)
    {
        bodyLength = 0;
        frameBytes = 0;
        error = null;

        if (frame.Length < MinFrameBytes)
        {
            error = $"Retail world frame is too short: {frame.Length}.";
            return false;
        }

        uint body = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(0, 4));
        if (body < 4 || body > MaxFrameBytes)
        {
            error = $"Retail world frame has invalid body length: {body}.";
            return false;
        }

        long total = HeaderBytes + (long)body;
        if (total > int.MaxValue || total > MaxFrameBytes)
        {
            error = $"Retail world frame has invalid total length: {total}.";
            return false;
        }

        bodyLength = (int)body;
        frameBytes = (int)total;
        if (frame.Length != frameBytes)
        {
            error = $"Retail world frame size mismatch: expected {frameBytes}, got {frame.Length}.";
            return false;
        }

        return true;
    }

    private static void WriteNonce(
        ulong counter,
        uint magic,
        Span<byte> nonce12,
        RetailWorldPacketCryptNonceLayout layout)
    {
        switch (layout)
        {
            case RetailWorldPacketCryptNonceLayout.CounterLeMagicLe:
                BinaryPrimitives.WriteUInt64LittleEndian(nonce12.Slice(0, 8), counter);
                BinaryPrimitives.WriteUInt32LittleEndian(nonce12.Slice(8, 4), magic);
                break;
            case RetailWorldPacketCryptNonceLayout.CounterBeMagicLe:
                BinaryPrimitives.WriteUInt64BigEndian(nonce12.Slice(0, 8), counter);
                BinaryPrimitives.WriteUInt32LittleEndian(nonce12.Slice(8, 4), magic);
                break;
            case RetailWorldPacketCryptNonceLayout.MagicLeCounterBe:
                BinaryPrimitives.WriteUInt32LittleEndian(nonce12.Slice(0, 4), magic);
                BinaryPrimitives.WriteUInt64BigEndian(nonce12.Slice(4, 8), counter);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(layout), layout, "Unsupported nonce layout.");
        }
    }

    private static RetailWorldPacketCryptNonceLayout ParseNonceLayout(string rawLayout)
    {
        if (string.IsNullOrWhiteSpace(rawLayout))
        {
            return RetailWorldPacketCryptNonceLayout.CounterLeMagicLe;
        }

        string normalized = rawLayout.Trim().ToLowerInvariant();
        return normalized switch
        {
            WorldGatewayProtocolConstants.RetailWorldPacketCryptNonceLayoutCounterLeMagicLe => RetailWorldPacketCryptNonceLayout.CounterLeMagicLe,
            WorldGatewayProtocolConstants.RetailWorldPacketCryptNonceLayoutCounterBeMagicLe => RetailWorldPacketCryptNonceLayout.CounterBeMagicLe,
            WorldGatewayProtocolConstants.RetailWorldPacketCryptNonceLayoutMagicLeCounterBe => RetailWorldPacketCryptNonceLayout.MagicLeCounterBe,
            _ => throw new ArgumentOutOfRangeException(
                nameof(rawLayout),
                rawLayout,
                "Unsupported RetailWorldPacketCrypt nonce layout. Allowed: counter_le_magic_le, counter_be_magic_le, magic_le_counter_be.")
        };
    }

    private static uint ParseServerNonceMagic(string rawMagic)
    {
        if (string.IsNullOrWhiteSpace(rawMagic))
        {
            return WorldGatewayProtocolConstants.RetailWorldPacketCryptServerNonceMagicUInt32;
        }

        string normalized = rawMagic.Trim().ToLowerInvariant();
        return normalized switch
        {
            WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultServerNonceMagic => WorldGatewayProtocolConstants.RetailWorldPacketCryptServerNonceMagicUInt32,
            WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultClientNonceMagic => WorldGatewayProtocolConstants.RetailWorldPacketCryptClientNonceMagicUInt32,
            _ => throw new ArgumentOutOfRangeException(
                nameof(rawMagic),
                rawMagic,
                "Unsupported RetailWorldPacketCrypt server nonce magic. Allowed: srvr, clnt.")
        };
    }

    private static uint ParseClientNonceMagic(string rawMagic)
    {
        if (string.IsNullOrWhiteSpace(rawMagic))
        {
            return WorldGatewayProtocolConstants.RetailWorldPacketCryptClientNonceMagicUInt32;
        }

        string normalized = rawMagic.Trim().ToLowerInvariant();
        return normalized switch
        {
            WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultClientNonceMagic => WorldGatewayProtocolConstants.RetailWorldPacketCryptClientNonceMagicUInt32,
            WorldGatewayProtocolConstants.RetailWorldPacketCryptDefaultServerNonceMagic => WorldGatewayProtocolConstants.RetailWorldPacketCryptServerNonceMagicUInt32,
            _ => throw new ArgumentOutOfRangeException(
                nameof(rawMagic),
                rawMagic,
                "Unsupported RetailWorldPacketCrypt client nonce magic. Allowed: clnt, srvr.")
        };
    }
}

