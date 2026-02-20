using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Adapter.AuthGateway;

/// <summary>
/// Asynchronous TCP listener for Retail auth traffic.
/// Uses PipeReader + ReadOnlySequence to avoid per-packet allocations.
/// </summary>
public sealed class AuthListener : BackgroundService
{
    private readonly ILogger<AuthListener> _logger;
    private readonly IAuthOpcodeDispatcher _dispatcher;
    private readonly IAuthSessionManager _sessionManager;
    private readonly IAuthPacketFramer _framer;
    private readonly X509Certificate2 _serverCertificate;
    private readonly AuthListenerOptions _options;

    private readonly object _activeConnectionsLock = new();
    private readonly List<Task> _activeConnections = new();

    private TcpListener? _listener;
    private int _connectionSequence;

    public AuthListener(
        ILogger<AuthListener> logger,
        IAuthOpcodeDispatcher dispatcher,
        IAuthSessionManager sessionManager,
        IAuthPacketFramer framer,
        X509Certificate2 serverCertificate,
        IOptions<AuthListenerOptions> options)
    {
        _logger = logger;
        _dispatcher = dispatcher;
        _sessionManager = sessionManager;
        _framer = framer;
        _serverCertificate = serverCertificate;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var bindAddress = ParseBindAddress(_options.BindAddress);
        _listener = new TcpListener(bindAddress, _options.Port);
        _listener.Server.NoDelay = true;
        _listener.Start(_options.Backlog);

        _logger.LogInformation(
            "AuthListener started on {Address}:{Port} (Backlog={Backlog}, MaxBnetHeaderBytes={MaxBnetHeaderBytes}, MaxPacketBodyBytes={MaxPacketBodyBytes})",
            bindAddress, _options.Port, _options.Backlog, _options.MaxBnetHeaderBytes, _options.MaxPacketBodyBytes);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                uint connectionId = unchecked((uint)Interlocked.Increment(ref _connectionSequence));
                var connectionTask = HandleConnectionAsync(client, connectionId, stoppingToken);

                lock (_activeConnectionsLock)
                {
                    _activeConnections.Add(connectionTask);
                }

                _ = connectionTask.ContinueWith(
                    _ =>
                    {
                        lock (_activeConnectionsLock)
                        {
                            _activeConnections.Remove(connectionTask);
                        }
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        finally
        {
            _listener.Stop();

            Task[] pending;
            lock (_activeConnectionsLock)
            {
                pending = _activeConnections.ToArray();
            }

            if (pending.Length > 0)
            {
                await Task.WhenAll(pending).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, uint connectionId, CancellationToken serverToken)
    {
        using (client)
        {
            client.NoDelay = true;

            var remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
            _logger.LogInformation("Auth connection opened: ConnectionId={ConnectionId}, Remote={Remote}", connectionId, remote);

            await using var networkStream = client.GetStream();
            await using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

            try
            {
                await sslStream.AuthenticateAsServerAsync(
                    _serverCertificate,
                    clientCertificateRequired: false,
                    enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                    checkCertificateRevocation: false).ConfigureAwait(false);
            }
            catch (AuthenticationException ex)
            {
                _logger.LogWarning(
                    ex,
                    "TLS Error on ConnectionId={ConnectionId}, Remote={Remote}. Closing connection.",
                    connectionId,
                    remote);
                return;
            }
            catch (IOException ex)
            {
                _logger.LogWarning(
                    ex,
                    "TLS Error on ConnectionId={ConnectionId}, Remote={Remote}. Closing connection.",
                    connectionId,
                    remote);
                return;
            }

            _logger.LogInformation(
                "TLS handshake completed: ConnectionId={ConnectionId}, Remote={Remote}",
                connectionId,
                remote);

            var reader = PipeReader.Create(
                sslStream,
                new StreamPipeReaderOptions(
                    bufferSize: _options.ReaderBufferSize,
                    minimumReadSize: _options.MinimumReadSize,
                    leaveOpen: true));

            // Keep a PipeWriter attached to the same transport from day one:
            // auth handlers will use it to send framed challenge/response packets.
            var writer = PipeWriter.Create(
                sslStream,
                new StreamPipeWriterOptions(
                    leaveOpen: true));

            var context = new AuthPacketContext(connectionId, remote, writer);

            try
            {
                while (!serverToken.IsCancellationRequested)
                {
                    ReadResult readResult = await reader.ReadAsync(serverToken).ConfigureAwait(false);
                    ReadOnlySequence<byte> buffer = readResult.Buffer;
                    bool disconnectRequested = false;

                    try
                    {
                        while (TryReadParsedPacket(buffer, out ParsedPacket parsedPacket))
                        {
                            AuthDispatchResult dispatchResult = await _dispatcher.DispatchAsync(
                                    context,
                                    parsedPacket.ServiceId,
                                    parsedPacket.ServiceHash,
                                    parsedPacket.MethodId,
                                    parsedPacket.Token,
                                    parsedPacket.Payload,
                                    serverToken)
                                .ConfigureAwait(false);

                            buffer = buffer.Slice(parsedPacket.Consumed);
                            if (dispatchResult == AuthDispatchResult.Disconnect)
                            {
                                disconnectRequested = true;
                                break;
                            }
                        }
                    }
                    catch (InvalidDataException ex)
                    {
                        _logger.LogWarning(
                            ex,
                            "Protocol error on ConnectionId={ConnectionId}, Remote={Remote}. Closing connection.",
                            connectionId,
                            remote);
                        break;
                    }
                    finally
                    {
                        // Commit bytes consumed by parsed packets and keep partial frame in buffer.
                        reader.AdvanceTo(buffer.Start, buffer.End);
                    }

                    if (disconnectRequested)
                    {
                        break;
                    }

                    if (readResult.IsCompleted)
                    {
                        break;
                    }
                }
            }
            catch (OperationCanceledException) when (serverToken.IsCancellationRequested)
            {
                // Graceful shutdown.
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Unhandled error in auth connection loop: ConnectionId={ConnectionId}, Remote={Remote}",
                    connectionId,
                    remote);
            }
            finally
            {
                _sessionManager.Remove(connectionId);
                await reader.CompleteAsync().ConfigureAwait(false);
                await writer.CompleteAsync().ConfigureAwait(false);
                _logger.LogInformation("Auth connection closed: ConnectionId={ConnectionId}, Remote={Remote}", connectionId, remote);
            }
        }
    }

    private static IPAddress ParseBindAddress(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value == "*" ||
            value == "0.0.0.0")
        {
            return IPAddress.Any;
        }

        if (value == "::" || value == "[::]")
        {
            return IPAddress.IPv6Any;
        }

        return IPAddress.Parse(value);
    }

    private bool TryReadParsedPacket(ReadOnlySequence<byte> buffer, out ParsedPacket packet)
    {
        SequenceReader<byte> sequenceReader = new(buffer);
        if (!_framer.TryReadPacket(ref sequenceReader, out BnetInboundPacket inboundPacket))
        {
            packet = default;
            return false;
        }

        packet = new ParsedPacket(
            sequenceReader.Position,
            inboundPacket.ServiceId,
            inboundPacket.ServiceHash,
            inboundPacket.MethodId,
            inboundPacket.Token,
            inboundPacket.Payload);
        return true;
    }

    private readonly record struct ParsedPacket(
        SequencePosition Consumed,
        uint ServiceId,
        uint ServiceHash,
        uint MethodId,
        uint Token,
        ReadOnlySequence<byte> Payload);
}

public sealed class AuthListenerOptions
{
    public const string SectionName = "AuthListener";

    public string BindAddress { get; init; } = "0.0.0.0";

    [Range(1, 65535)]
    public int Port { get; init; } = 3724;

    [Range(1, 8192)]
    public int Backlog { get; init; } = 1024;

    [Range(1024, 1024 * 1024)]
    public int ReaderBufferSize { get; init; } = 64 * 1024;

    [Range(256, 128 * 1024)]
    public int MinimumReadSize { get; init; } = 2048;

    // Maximum accepted payload size for one Bnet frame body.
    [Range(16, 16 * 1024 * 1024)]
    public int MaxPacketBodyBytes { get; init; } = 512 * 1024;

    [Range(32, 65535)]
    public int MaxBnetHeaderBytes { get; init; } = 4096;
}

public sealed class AuthPacketContext
{
    private int _serverRequestTokenSequence;
    private readonly ConcurrentDictionary<string, object> _items = new(StringComparer.Ordinal);

    public AuthPacketContext(uint connectionId, string remoteEndpoint, PipeWriter writer)
    {
        ConnectionId = connectionId;
        RemoteEndpoint = remoteEndpoint;
        Writer = writer;
    }

    public uint ConnectionId { get; }
    public string RemoteEndpoint { get; }
    public PipeWriter Writer { get; }

    public void SetValue<T>(string key, T value)
        where T : notnull
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        _items[key] = value;
    }

    public bool TryGetValue<T>(string key, out T value)
    {
        value = default!;

        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        if (_items.TryGetValue(key, out object? boxed) && boxed is T typed)
        {
            value = typed;
            return true;
        }

        return false;
    }

    public async ValueTask SendPacketAsync(
        uint opcode,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        uint bodyLength = checked((uint)(sizeof(uint) + payload.Length));
        Span<byte> header = stackalloc byte[sizeof(uint) * 2];
        BinaryPrimitives.WriteUInt32LittleEndian(header, bodyLength);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(sizeof(uint)), opcode);

        Writer.Write(header);
        if (!payload.IsEmpty)
        {
            Writer.Write(payload.Span);
        }

        FlushResult flushResult = await Writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (flushResult.IsCanceled)
        {
            throw new OperationCanceledException(cancellationToken);
        }
    }

    public async ValueTask SendBnetResponseAsync(
        uint token,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        var headerWriter = new ArrayBufferWriter<byte>(64);
        BnetResponseHeaderBuilder.WritePayloadResponseHeader(headerWriter, token, payload.Length);

        if (headerWriter.WrittenCount > ushort.MaxValue)
        {
            throw new InvalidDataException($"Bnet response header is too large: {headerWriter.WrittenCount}.");
        }

        Span<byte> prefix = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)headerWriter.WrittenCount);

        Writer.Write(prefix);
        Writer.Write(headerWriter.WrittenSpan);
        if (!payload.IsEmpty)
        {
            Writer.Write(payload.Span);
        }

        FlushResult flushResult = await Writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (flushResult.IsCanceled)
        {
            throw new OperationCanceledException(cancellationToken);
        }
    }

    public async ValueTask SendBnetStatusAsync(
        uint token,
        uint status,
        CancellationToken cancellationToken = default)
    {
        var headerWriter = new ArrayBufferWriter<byte>(32);
        BnetResponseHeaderBuilder.WriteStatusResponseHeader(headerWriter, token, status);

        if (headerWriter.WrittenCount > ushort.MaxValue)
        {
            throw new InvalidDataException($"Bnet status header is too large: {headerWriter.WrittenCount}.");
        }

        Span<byte> prefix = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)headerWriter.WrittenCount);

        Writer.Write(prefix);
        Writer.Write(headerWriter.WrittenSpan);

        FlushResult flushResult = await Writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (flushResult.IsCanceled)
        {
            throw new OperationCanceledException(cancellationToken);
        }
    }

    public async ValueTask SendBnetRequestAsync(
        uint serviceHash,
        uint methodId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default)
    {
        uint requestToken = unchecked((uint)Interlocked.Increment(ref _serverRequestTokenSequence));

        var headerWriter = new ArrayBufferWriter<byte>(64);
        BnetRequestHeaderBuilder.WriteRequestHeader(headerWriter, serviceHash, methodId, requestToken, payload.Length);

        if (headerWriter.WrittenCount > ushort.MaxValue)
        {
            throw new InvalidDataException($"Bnet request header is too large: {headerWriter.WrittenCount}.");
        }

        Span<byte> prefix = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, (ushort)headerWriter.WrittenCount);

        Writer.Write(prefix);
        Writer.Write(headerWriter.WrittenSpan);
        if (!payload.IsEmpty)
        {
            Writer.Write(payload.Span);
        }

        FlushResult flushResult = await Writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (flushResult.IsCanceled)
        {
            throw new OperationCanceledException(cancellationToken);
        }
    }
}

public interface IAuthPacketFramer
{
    bool TryReadPacket(ref SequenceReader<byte> reader, out BnetInboundPacket packet);
}

public readonly record struct BnetInboundPacket(
    uint ServiceId,
    uint ServiceHash,
    uint MethodId,
    uint Token,
    ReadOnlySequence<byte> Payload);

internal readonly record struct BnetFrameHeader(
    uint ServiceId,
    uint ServiceHash,
    uint MethodId,
    uint Token,
    int PayloadSize);

public sealed class BnetPacketFramer : IAuthPacketFramer
{
    private const int HeaderStackLimit = 512;

    private readonly int _maxHeaderBytes;
    private readonly int _maxPayloadBytes;

    public BnetPacketFramer(int maxHeaderBytes, int maxPayloadBytes)
    {
        _maxHeaderBytes = maxHeaderBytes;
        _maxPayloadBytes = maxPayloadBytes;
    }

    public bool TryReadPacket(ref SequenceReader<byte> reader, out BnetInboundPacket packet)
    {
        packet = default;

        var cursor = reader;
        if (!TryReadUInt16BigEndian(ref cursor, out ushort headerLength))
        {
            return false;
        }

        if (headerLength == 0 || headerLength > _maxHeaderBytes)
        {
            throw new InvalidDataException($"Invalid Bnet header length: {headerLength}.");
        }

        if (cursor.Remaining < headerLength)
        {
            return false;
        }

        ReadOnlySequence<byte> headerSequence = cursor.Sequence.Slice(cursor.Position, headerLength);
        if (!TryParseHeader(headerSequence, out BnetFrameHeader header))
        {
            throw new InvalidDataException("Malformed Bnet protobuf header.");
        }

        if (header.PayloadSize < 0 || header.PayloadSize > _maxPayloadBytes)
        {
            throw new InvalidDataException($"Invalid Bnet payload length: {header.PayloadSize}.");
        }

        cursor.Advance(headerLength);

        if (cursor.Remaining < header.PayloadSize)
        {
            return false;
        }

        ReadOnlySequence<byte> payload = cursor.Sequence.Slice(cursor.Position, header.PayloadSize);
        cursor.Advance(header.PayloadSize);

        reader = cursor;
        packet = new BnetInboundPacket(header.ServiceId, header.ServiceHash, header.MethodId, header.Token, payload);
        return true;
    }

    private static bool TryReadUInt16BigEndian(ref SequenceReader<byte> reader, out ushort value)
    {
        if (reader.Remaining < sizeof(ushort))
        {
            value = 0;
            return false;
        }

        Span<byte> tmp = stackalloc byte[sizeof(ushort)];
        if (!reader.TryCopyTo(tmp))
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadUInt16BigEndian(tmp);
        reader.Advance(sizeof(ushort));
        return true;
    }

    private static bool TryParseHeader(ReadOnlySequence<byte> headerSequence, out BnetFrameHeader header)
    {
        if (headerSequence.IsSingleSegment)
        {
            return TryParseHeader(headerSequence.FirstSpan, out header);
        }

        int length = checked((int)headerSequence.Length);
        if (length <= HeaderStackLimit)
        {
            Span<byte> tmp = stackalloc byte[length];
            headerSequence.CopyTo(tmp);
            return TryParseHeader(tmp, out header);
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Span<byte> span = rented.AsSpan(0, length);
            headerSequence.CopyTo(span);
            return TryParseHeader(span, out header);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static bool TryParseHeader(ReadOnlySpan<byte> headerBytes, out BnetFrameHeader header)
    {
        header = default;

        var reader = new ProtobufVarintReader(headerBytes);
        uint serviceId = 0;
        uint serviceHash = 0;
        uint methodId = 0;
        uint token = 0;
        int payloadSize = 0;

        bool hasService = false;
        bool hasToken = false;

        while (!reader.End)
        {
            if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
            {
                return false;
            }

            switch (wireType)
            {
                case ProtobufWireType.Varint:
                    if (!reader.TryReadVarint(out ulong varintValue))
                    {
                        return false;
                    }

                    switch (fieldNumber)
                    {
                        case 1:
                            if (varintValue > uint.MaxValue)
                            {
                                return false;
                            }

                            serviceId = (uint)varintValue;
                            hasService = true;
                            break;
                        case 2:
                            if (varintValue > uint.MaxValue)
                            {
                                return false;
                            }

                            methodId = (uint)varintValue;
                            break;
                        case 3:
                            if (varintValue > uint.MaxValue)
                            {
                                return false;
                            }

                            token = (uint)varintValue;
                            hasToken = true;
                            break;
                        case 5:
                            if (varintValue > int.MaxValue)
                            {
                                return false;
                            }

                            payloadSize = (int)varintValue;
                            break;
                        case 11:
                            if (varintValue > uint.MaxValue)
                            {
                                return false;
                            }

                            // Compatibility path: some custom gateways may encode this as varint.
                            serviceHash = (uint)varintValue;
                            break;
                    }

                    break;
                case ProtobufWireType.Fixed64:
                    if (!reader.TrySkip(8))
                    {
                        return false;
                    }

                    break;
                case ProtobufWireType.LengthDelimited:
                    if (!reader.TrySkipLengthDelimited())
                    {
                        return false;
                    }

                    break;
                case ProtobufWireType.Fixed32:
                    if (fieldNumber == 11)
                    {
                        if (!reader.TryReadFixed32(out uint fixedValue))
                        {
                            return false;
                        }

                        serviceHash = fixedValue;
                    }
                    else if (!reader.TrySkip(4))
                    {
                        return false;
                    }

                    break;
                default:
                    return false;
            }
        }

        if (!hasService || !hasToken)
        {
            return false;
        }

        header = new BnetFrameHeader(serviceId, serviceHash, methodId, token, payloadSize);
        return true;
    }
}

internal enum ProtobufWireType : byte
{
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    StartGroup = 3,
    EndGroup = 4,
    Fixed32 = 5
}

internal ref struct ProtobufVarintReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _offset;

    public ProtobufVarintReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _offset = 0;
    }

    public bool End => _offset >= _buffer.Length;

    public bool TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType)
    {
        fieldNumber = 0;
        wireType = default;

        if (!TryReadVarint(out ulong rawTag) || rawTag == 0)
        {
            return false;
        }

        fieldNumber = (uint)(rawTag >> 3);
        wireType = (ProtobufWireType)(rawTag & 0b111);
        return fieldNumber != 0;
    }

    public bool TryReadVarint(out ulong value)
    {
        value = 0;
        int shift = 0;

        while (shift < 64 && _offset < _buffer.Length)
        {
            byte current = _buffer[_offset++];
            value |= ((ulong)(current & 0x7F)) << shift;
            if ((current & 0x80) == 0)
            {
                return true;
            }

            shift += 7;
        }

        return false;
    }

    public bool TrySkip(int count)
    {
        if (count < 0 || _offset > _buffer.Length - count)
        {
            return false;
        }

        _offset += count;
        return true;
    }

    public bool TrySkipLengthDelimited()
    {
        if (!TryReadVarint(out ulong length) || length > int.MaxValue)
        {
            return false;
        }

        return TrySkip((int)length);
    }

    public bool TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> value)
    {
        value = default;
        if (!TryReadVarint(out ulong length) || length > int.MaxValue)
        {
            return false;
        }

        int intLength = (int)length;
        if (intLength < 0 || _offset > _buffer.Length - intLength)
        {
            return false;
        }

        value = _buffer.Slice(_offset, intLength);
        _offset += intLength;
        return true;
    }

    public bool TryReadFixed32(out uint value)
    {
        value = 0;
        if (_offset > _buffer.Length - sizeof(uint))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_offset, sizeof(uint)));
        _offset += sizeof(uint);
        return true;
    }

    public bool TrySkipField(ProtobufWireType wireType)
    {
        switch (wireType)
        {
            case ProtobufWireType.Varint:
                return TryReadVarint(out _);
            case ProtobufWireType.Fixed64:
                return TrySkip(8);
            case ProtobufWireType.LengthDelimited:
                return TrySkipLengthDelimited();
            case ProtobufWireType.Fixed32:
                return TrySkip(4);
            default:
                return false;
        }
    }
}
