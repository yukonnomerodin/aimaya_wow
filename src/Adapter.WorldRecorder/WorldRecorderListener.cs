
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Adapter.WorldRecorder;

public sealed class WorldRecorderListener : BackgroundService
{
    private const uint RetailOpcodeAuthSession = 0x0041_0001;
    private const uint RetailOpcodeEnterEncryptedModeAck = 0x0041_0005;
    private const uint RetailOpcodeLogDisconnect = 0x0041_0007;
    private const uint RetailOpcodeSmsgAuthResponse = 0x0042_0001;

    private readonly ILogger<WorldRecorderListener> _logger;
    private readonly WorldRecorderOptions _options;
    private readonly HashSet<uint> _enterEncryptedHints;

    private readonly object _gate = new();
    private readonly List<Task> _active = [];
    private TcpListener? _listener;
    private int _sequence;

    public WorldRecorderListener(ILogger<WorldRecorderListener> logger, IOptions<WorldRecorderOptions> options)
    {
        _logger = logger;
        _options = options.Value;
        _enterEncryptedHints = ParseHints(_options.EnterEncryptedOpcodeHints);
        if (_enterEncryptedHints.Count == 0)
        {
            _enterEncryptedHints.Add(0x0049_0004);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        IPAddress bindAddress = IPAddress.TryParse(_options.ListenAddress, out IPAddress? ip) ? ip : IPAddress.Any;
        _listener = new TcpListener(bindAddress, _options.ListenPort);
        _listener.Server.NoDelay = true;
        _listener.Start(_options.Backlog);

        _logger.LogInformation(
            "WorldRecorder started on {ListenAddress}:{ListenPort} -> {UpstreamAddress}:{UpstreamPort} (Runlogs={RunlogsRootPath}, Raw={EnableRawCapture}, Hints={Hints})",
            bindAddress,
            _options.ListenPort,
            _options.UpstreamAddress,
            _options.UpstreamPort,
            _options.RunlogsRootPath,
            _options.EnableRawCapture,
            string.Join(", ", _enterEncryptedHints.Select(static x => $"0x{x:X8}")));

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient downstream;
                try
                {
                    downstream = await _listener.AcceptTcpClientAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                uint connectionId = unchecked((uint)Interlocked.Increment(ref _sequence));
                Task task = HandleConnectionAsync(downstream, connectionId, stoppingToken);

                lock (_gate)
                {
                    _active.Add(task);
                }

                _ = task.ContinueWith(_ =>
                {
                    lock (_gate)
                    {
                        _active.Remove(task);
                    }
                }, TaskScheduler.Default);
            }
        }
        finally
        {
            _listener.Stop();
            Task[] pending;
            lock (_gate)
            {
                pending = _active.ToArray();
            }

            if (pending.Length > 0)
            {
                await Task.WhenAll(pending).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleConnectionAsync(TcpClient downstreamClient, uint connectionId, CancellationToken serverToken)
    {
        using (downstreamClient)
        {
            downstreamClient.NoDelay = true;
            string downRemote = downstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            _logger.LogInformation("Recorder connection opened: ConnectionId={ConnectionId}, Downstream={Downstream}", connectionId, downRemote);

            using var upstreamClient = new TcpClient(AddressFamily.InterNetwork);
            upstreamClient.NoDelay = true;

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                connectCts.CancelAfter(_options.UpstreamConnectTimeoutMs);
                await upstreamClient.ConnectAsync(_options.UpstreamAddress, _options.UpstreamPort, connectCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException)
            {
                _logger.LogWarning(ex, "Recorder upstream connect failed: ConnectionId={ConnectionId}", connectionId);
                return;
            }

            string upRemote = upstreamClient.Client.RemoteEndPoint?.ToString() ?? "unknown";
            _logger.LogInformation("Recorder upstream connected: ConnectionId={ConnectionId}, Upstream={Upstream}", connectionId, upRemote);

            DateTimeOffset openedAt = DateTimeOffset.UtcNow;
            string stamp = openedAt.ToString("yyyyMMddTHHmmssfffZ", CultureInfo.InvariantCulture);
            string runRoot = ResolvePath(_options.RunlogsRootPath);
            Directory.CreateDirectory(runRoot);

            string rawC2WPath = Path.Combine(runRoot, $"world_recorder.c2w.{stamp}.conn{connectionId}.bin");
            string rawW2CPath = Path.Combine(runRoot, $"world_recorder.w2c.{stamp}.conn{connectionId}.bin");

            await using NetworkStream downStream = downstreamClient.GetStream();
            await using NetworkStream upStream = upstreamClient.GetStream();
            await using FileStream? rawC2W = _options.EnableRawCapture ? OpenRaw(rawC2WPath) : null;
            await using FileStream? rawW2C = _options.EnableRawCapture ? OpenRaw(rawW2CPath) : null;

            var capture = new Capture(connectionId, openedAt, _options.MaxFrameEvents, _options.EnablePerFrameLogs, _enterEncryptedHints, _logger);
            var parserC2W = new RetailFrameParser(_options.MaxFrameBytes, frame => capture.OnFrame(Direction.ClientToWorld, frame));
            var parserW2C = new RetailFrameParser(_options.MaxFrameBytes, frame => capture.OnFrame(Direction.WorldToClient, frame));

            using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
            Task<long> tC2W = RelayAsync(downStream, upStream, rawC2W, parserC2W, relayCts.Token);
            Task<long> tW2C = RelayAsync(upStream, downStream, rawW2C, parserW2C, relayCts.Token);

            try
            {
                _ = await Task.WhenAny(tC2W, tW2C).ConfigureAwait(false);
            }
            finally
            {
                relayCts.Cancel();
                TryShutdown(downstreamClient);
                TryShutdown(upstreamClient);
            }

            long bytesC2W = await SafeResultAsync(tC2W).ConfigureAwait(false);
            long bytesW2C = await SafeResultAsync(tW2C).ConfigureAwait(false);
            DateTimeOffset closedAt = DateTimeOffset.UtcNow;

            ReportArtifacts artifacts = capture.WriteArtifacts(
                runRoot,
                closedAt,
                bytesC2W,
                bytesW2C,
                _options.UpstreamAddress,
                _options.UpstreamPort,
                _options.EnableRawCapture ? rawC2WPath : null,
                _options.EnableRawCapture ? rawW2CPath : null);

            _logger.LogInformation(
                "Recorder connection closed: ConnectionId={ConnectionId}, BytesClientToWorld={BytesClientToWorld}, BytesWorldToClient={BytesWorldToClient}, Report={Report}",
                connectionId,
                bytesC2W,
                bytesW2C,
                artifacts.ReportPath);

            if (artifacts.GoldenHexPath is not null)
            {
                _logger.LogInformation(
                    "[WorldRecorder][GOLDEN] Payload captured. ConnectionId={ConnectionId}, Hex={Hex}, Meta={Meta}, Diff={Diff}",
                    connectionId,
                    artifacts.GoldenHexPath,
                    artifacts.GoldenMetadataPath,
                    artifacts.DiffPath ?? "<none>");
            }
        }
    }

    private async Task<long> RelayAsync(NetworkStream source, NetworkStream destination, FileStream? rawCapture, RetailFrameParser parser, CancellationToken token)
    {
        byte[] buffer = GC.AllocateUninitializedArray<byte>(_options.RelayBufferBytes);
        long total = 0;

        try
        {
            while (!token.IsCancellationRequested)
            {
                int read;
                try
                {
                    read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    break;
                }

                if (read <= 0)
                {
                    break;
                }

                ReadOnlyMemory<byte> chunk = buffer.AsMemory(0, read);
                if (rawCapture is not null)
                {
                    await rawCapture.WriteAsync(chunk, token).ConfigureAwait(false);
                }

                parser.Append(chunk.Span);
                await destination.WriteAsync(chunk, token).ConfigureAwait(false);
                total += read;
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // expected
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            _logger.LogDebug(ex, "Recorder relay terminated with IO/socket error.");
        }

        return total;
    }

    private static async Task<long> SafeResultAsync(Task<long> task)
    {
        try
        {
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
    }

    private static FileStream OpenRaw(string path)
    {
        return new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
    }

    private static void TryShutdown(TcpClient client)
    {
        try
        {
            if (client.Client.Connected)
            {
                client.Client.Shutdown(SocketShutdown.Both);
            }
        }
        catch (SocketException)
        {
            // no-op
        }
        catch (ObjectDisposedException)
        {
            // no-op
        }
    }

    private static string ResolvePath(string path)
    {
        if (Path.IsPathRooted(path))
        {
            return path;
        }

        return Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), path));
    }

    private static HashSet<uint> ParseHints(IEnumerable<string> raw)
    {
        var result = new HashSet<uint>();
        foreach (string item in raw)
        {
            if (TryParseFlexibleUInt32(item, out uint value))
            {
                result.Add(value);
            }
        }

        return result;
    }

    private static bool TryParseFlexibleUInt32(string value, out uint parsed)
    {
        parsed = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmed = value.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(trimmed.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out parsed);
        }

        return uint.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
    }

    private static string OpcodeHex(uint opcode) => $"0x{opcode:X8}";

    private enum Direction
    {
        ClientToWorld,
        WorldToClient
    }

    private readonly record struct RetailFrame(uint Opcode, byte[] Payload);

    private readonly record struct FrameEvent(
        long ElapsedMs,
        string Direction,
        string Opcode,
        int PayloadBytes,
        string PayloadHeadHex,
        string? Semantic);

    private readonly record struct ReportArtifacts(
        string ReportPath,
        string FramesPath,
        string? GoldenHexPath,
        string? GoldenMetadataPath,
        string? DiffPath);

    private readonly record struct GoldenFrame(uint Opcode, byte[] Payload, long ElapsedMs);

    private sealed class Capture
    {
        private readonly uint _connectionId;
        private readonly DateTimeOffset _openedAt;
        private readonly int _maxFrameEvents;
        private readonly bool _perFrameLogs;
        private readonly HashSet<uint> _hints;
        private readonly ILogger _logger;
        private readonly object _sync = new();

        private readonly List<FrameEvent> _frames = [];
        private int _framesDropped;

        private bool _ackObserved;
        private long? _ackElapsedMs;
        private int? _disconnectReason;
        private long? _disconnectElapsedMs;
        private GoldenFrame? _golden;

        public Capture(uint connectionId, DateTimeOffset openedAt, int maxFrameEvents, bool perFrameLogs, HashSet<uint> hints, ILogger logger)
        {
            _connectionId = connectionId;
            _openedAt = openedAt;
            _maxFrameEvents = maxFrameEvents;
            _perFrameLogs = perFrameLogs;
            _hints = hints;
            _logger = logger;
        }

        public void OnFrame(Direction direction, RetailFrame frame)
        {
            long elapsedMs = Math.Max(0, (long)(DateTimeOffset.UtcNow - _openedAt).TotalMilliseconds);
            string directionText = direction == Direction.ClientToWorld ? "client->world" : "world->client";
            string semantic = Describe(direction, frame.Opcode) ?? "<unknown>";

            lock (_sync)
            {
                if (_frames.Count < _maxFrameEvents)
                {
                    _frames.Add(new FrameEvent(
                        elapsedMs,
                        directionText,
                        OpcodeHex(frame.Opcode),
                        frame.Payload.Length,
                        Convert.ToHexString(frame.Payload.AsSpan(0, Math.Min(frame.Payload.Length, 64))),
                        semantic == "<unknown>" ? null : semantic));
                }
                else
                {
                    _framesDropped++;
                }

                if (direction == Direction.ClientToWorld && frame.Opcode == RetailOpcodeEnterEncryptedModeAck && !_ackObserved)
                {
                    _ackObserved = true;
                    _ackElapsedMs = elapsedMs;
                }

                if (direction == Direction.ClientToWorld && frame.Opcode == RetailOpcodeLogDisconnect && _disconnectReason is null && frame.Payload.Length >= 4)
                {
                    _disconnectReason = unchecked((int)BinaryPrimitives.ReadUInt32LittleEndian(frame.Payload.AsSpan(0, 4)));
                    _disconnectElapsedMs = elapsedMs;
                }

                if (direction == Direction.WorldToClient && _golden is null && _hints.Contains(frame.Opcode))
                {
                    _golden = new GoldenFrame(frame.Opcode, frame.Payload, elapsedMs);
                }
            }

            if (_perFrameLogs)
            {
                _logger.LogInformation(
                    "[WorldRecorder][FRAME] ConnectionId={ConnectionId}, Direction={Direction}, Opcode={Opcode}, PayloadBytes={PayloadBytes}, Semantic={Semantic}",
                    _connectionId,
                    directionText,
                    OpcodeHex(frame.Opcode),
                    frame.Payload.Length,
                    semantic);
            }
        }

        public ReportArtifacts WriteArtifacts(
            string runRoot,
            DateTimeOffset closedAt,
            long bytesC2W,
            long bytesW2C,
            string upstreamAddress,
            int upstreamPort,
            string? rawC2WPath,
            string? rawW2CPath)
        {
            string stamp = closedAt.ToString("yyyyMMddTHHmmssfffZ", CultureInfo.InvariantCulture);
            string framesPath = Path.Combine(runRoot, $"world_recorder.frames.{stamp}.conn{_connectionId}.json");
            WriteJson(framesPath, BuildFramesDoc());

            bool ack;
            long? ackMs;
            int? reason;
            long? reasonMs;
            int dropped;
            GoldenFrame? golden;

            lock (_sync)
            {
                ack = _ackObserved;
                ackMs = _ackElapsedMs;
                reason = _disconnectReason;
                reasonMs = _disconnectElapsedMs;
                dropped = _framesDropped;
                golden = _golden;
            }

            string? goldenHexPath = null;
            string? goldenMetaPath = null;
            string? diffPath = null;

            if (golden is GoldenFrame enter)
            {
                goldenHexPath = Path.Combine(runRoot, $"enter_encrypted_mode.golden.{stamp}.conn{_connectionId}.hex");
                goldenMetaPath = Path.Combine(runRoot, $"enter_encrypted_mode.golden.{stamp}.conn{_connectionId}.json");

                File.WriteAllText(goldenHexPath, Convert.ToHexString(enter.Payload));
                WriteJson(goldenMetaPath, new Dictionary<string, object?>
                {
                    ["timestamp_utc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    ["connection_id"] = _connectionId,
                    ["opcode"] = OpcodeHex(enter.Opcode),
                    ["payload_bytes"] = enter.Payload.Length,
                    ["payload_hex"] = Convert.ToHexString(enter.Payload),
                    ["captured_elapsed_ms"] = enter.ElapsedMs
                });

                diffPath = WriteDiff(runRoot, stamp, enter);
            }

            string reportPath = Path.Combine(runRoot, $"world_recorder.handshake.{stamp}.conn{_connectionId}.json");
            WriteJson(reportPath, new Dictionary<string, object?>
            {
                ["timestamp_utc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                ["connection_id"] = _connectionId,
                ["ack_observed"] = ack,
                ["ack_confirmed_elapsed_ms"] = ackMs,
                ["disconnect_reason"] = reason,
                ["disconnect_elapsed_ms"] = reasonMs,
                ["enter_encrypted_observed"] = golden is not null,
                ["enter_encrypted_opcode"] = golden is null ? null : OpcodeHex(golden.Value.Opcode),
                ["enter_encrypted_payload_bytes"] = golden?.Payload.Length,
                ["enter_encrypted_payload_hex_path"] = goldenHexPath,
                ["enter_encrypted_payload_metadata_path"] = goldenMetaPath,
                ["golden_vs_bridge_diff_path"] = diffPath,
                ["frame_events_path"] = framesPath,
                ["frame_events_dropped"] = dropped,
                ["bytes_client_to_world"] = bytesC2W,
                ["bytes_world_to_client"] = bytesW2C,
                ["raw_client_to_world_path"] = rawC2WPath,
                ["raw_world_to_client_path"] = rawW2CPath,
                ["connection_opened_at_utc"] = _openedAt.ToString("O", CultureInfo.InvariantCulture),
                ["connection_closed_at_utc"] = closedAt.ToString("O", CultureInfo.InvariantCulture),
                ["connection_duration_ms"] = Math.Max(0, (long)(closedAt - _openedAt).TotalMilliseconds),
                ["recorder_upstream"] = $"{upstreamAddress}:{upstreamPort}"
            });

            return new ReportArtifacts(reportPath, framesPath, goldenHexPath, goldenMetaPath, diffPath);
        }

        private object BuildFramesDoc()
        {
            lock (_sync)
            {
                return new Dictionary<string, object?>
                {
                    ["connection_id"] = _connectionId,
                    ["captured_at_utc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                    ["frame_count"] = _frames.Count,
                    ["frame_events"] = _frames
                };
            }
        }

        private string WriteDiff(string runRoot, string stamp, GoldenFrame golden)
        {
            string diffPath = Path.Combine(runRoot, $"enter_encrypted_mode.golden_vs_bridge.diff.{stamp}.conn{_connectionId}.txt");
            string? bridgePath = Directory
                .GetFiles(runRoot, "enter_encrypted_mode.sent.*.json", SearchOption.TopDirectoryOnly)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();

            var sb = new StringBuilder();
            sb.AppendLine($"golden_opcode={OpcodeHex(golden.Opcode)}");
            sb.AppendLine($"golden_len={golden.Payload.Length}");

            if (bridgePath is null)
            {
                sb.AppendLine("status=no_bridge_proof");
                File.WriteAllText(diffPath, sb.ToString());
                return diffPath;
            }

            sb.AppendLine($"bridge_proof_path={bridgePath}");
            if (!TryLoadBridgePayload(bridgePath, out string? bridgeOpcode, out byte[] bridgePayload, out string? error))
            {
                sb.AppendLine("status=bridge_proof_parse_failed");
                sb.AppendLine($"error={error}");
                File.WriteAllText(diffPath, sb.ToString());
                return diffPath;
            }

            sb.AppendLine($"bridge_opcode={bridgeOpcode}");
            sb.AppendLine($"bridge_len={bridgePayload.Length}");

            int common = Math.Min(golden.Payload.Length, bridgePayload.Length);
            int diffCount = Math.Abs(golden.Payload.Length - bridgePayload.Length);
            var first = new List<string>();

            for (int i = 0; i < common; i++)
            {
                if (golden.Payload[i] != bridgePayload[i])
                {
                    diffCount++;
                    if (first.Count < 32)
                    {
                        first.Add($"idx={i}: golden={golden.Payload[i]:X2} bridge={bridgePayload[i]:X2}");
                    }
                }
            }

            sb.AppendLine($"byte_diff_count={diffCount}");
            sb.AppendLine(diffCount == 0 ? "status=match" : "status=mismatch");
            if (first.Count > 0)
            {
                sb.AppendLine("first_differences:");
                foreach (string line in first)
                {
                    sb.AppendLine(line);
                }
            }

            File.WriteAllText(diffPath, sb.ToString());
            return diffPath;
        }

        private static bool TryLoadBridgePayload(string metadataPath, out string? opcode, out byte[] payload, out string? error)
        {
            opcode = null;
            payload = Array.Empty<byte>();
            error = null;

            try
            {
                using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(metadataPath));
                JsonElement root = doc.RootElement;

                if (root.TryGetProperty("retail_opcode", out JsonElement op))
                {
                    opcode = op.GetString();
                }

                if (!root.TryGetProperty("payload_hex", out JsonElement hexElement))
                {
                    error = "payload_hex missing";
                    return false;
                }

                string? hex = hexElement.GetString();
                if (string.IsNullOrWhiteSpace(hex))
                {
                    error = "payload_hex empty";
                    return false;
                }

                payload = Convert.FromHexString(hex.Trim());
                return true;
            }
            catch (Exception ex) when (ex is IOException or JsonException or FormatException)
            {
                error = ex.Message;
                return false;
            }
        }

        private static string? Describe(Direction direction, uint opcode)
        {
            if (direction == Direction.ClientToWorld)
            {
                if (opcode == RetailOpcodeAuthSession)
                {
                    return "CMSG_AUTH_SESSION";
                }

                if (opcode == RetailOpcodeEnterEncryptedModeAck)
                {
                    return "CMSG_ENTER_ENCRYPTED_MODE_ACK";
                }

                if (opcode == RetailOpcodeLogDisconnect)
                {
                    return "CMSG_LOG_DISCONNECT";
                }

                return null;
            }

            if (opcode == RetailOpcodeSmsgAuthResponse)
            {
                return "SMSG_AUTH_RESPONSE";
            }

            return null;
        }

        private static void WriteJson(string path, object value)
        {
            string json = JsonSerializer.Serialize(value, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(path, json);
        }
    }

    private sealed class RetailFrameParser
    {
        private static readonly byte[] ClientConnectionInitializer = Encoding.ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2\n");
        private static readonly byte[] ServerConnectionInitializer = Encoding.ASCII.GetBytes("WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2\n");

        private readonly int _maxFrameBytes;
        private readonly Action<RetailFrame> _onFrame;
        private byte[] _buffer = GC.AllocateUninitializedArray<byte>(64 * 1024);
        private int _length;
        private bool _initializerProcessed;

        public RetailFrameParser(int maxFrameBytes, Action<RetailFrame> onFrame)
        {
            _maxFrameBytes = maxFrameBytes;
            _onFrame = onFrame;
        }

        public void Append(ReadOnlySpan<byte> chunk)
        {
            if (chunk.IsEmpty)
            {
                return;
            }

            EnsureCapacity(chunk.Length);
            chunk.CopyTo(_buffer.AsSpan(_length));
            _length += chunk.Length;

            while (true)
            {
                if (!_initializerProcessed)
                {
                    if (!TryProcessInitializer())
                    {
                        return;
                    }
                }

                if (_length < 20)
                {
                    return;
                }

                uint bodyLength = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(0, 4));
                if (bodyLength < 4 || bodyLength > _maxFrameBytes)
                {
                    Consume(1);
                    continue;
                }

                int frameBytes = checked(16 + (int)bodyLength);
                if (frameBytes <= 20 || frameBytes > _maxFrameBytes + 16)
                {
                    Consume(1);
                    continue;
                }

                if (_length < frameBytes)
                {
                    return;
                }

                uint opcode = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan(16, 4));
                int payloadBytes = checked((int)bodyLength - 4);
                byte[] payload = GC.AllocateUninitializedArray<byte>(payloadBytes);
                if (payloadBytes > 0)
                {
                    _buffer.AsSpan(20, payloadBytes).CopyTo(payload);
                }

                _onFrame(new RetailFrame(opcode, payload));
                Consume(frameBytes);
            }
        }

        private bool TryProcessInitializer()
        {
            if (_length == 0)
            {
                return false;
            }

            if (_buffer[0] != (byte)'W')
            {
                _initializerProcessed = true;
                return true;
            }

            int newlineIndex = Array.IndexOf(_buffer, (byte)'\n', 0, _length);
            if (newlineIndex < 0)
            {
                if (_length > 512)
                {
                    // Unexpected long text preface: fail open into frame parse mode.
                    _initializerProcessed = true;
                    return true;
                }

                return false;
            }

            int lineLength = newlineIndex + 1;
            ReadOnlySpan<byte> line = _buffer.AsSpan(0, lineLength);

            if (line.SequenceEqual(ClientConnectionInitializer) || line.SequenceEqual(ServerConnectionInitializer))
            {
                Consume(lineLength);
                _initializerProcessed = true;
                return true;
            }

            string text = Encoding.ASCII.GetString(line);
            if (text.StartsWith("WORLD OF WARCRAFT CONNECTION - ", StringComparison.Ordinal))
            {
                Consume(lineLength);
                _initializerProcessed = true;
                return true;
            }

            _initializerProcessed = true;
            return true;
        }

        private void EnsureCapacity(int appendBytes)
        {
            int needed = _length + appendBytes;
            if (needed <= _buffer.Length)
            {
                return;
            }

            int newLength = _buffer.Length;
            while (newLength < needed)
            {
                newLength = checked(newLength * 2);
            }

            Array.Resize(ref _buffer, newLength);
        }

        private void Consume(int bytes)
        {
            int remaining = _length - bytes;
            if (remaining > 0)
            {
                Buffer.BlockCopy(_buffer, bytes, _buffer, 0, remaining);
            }

            _length = remaining;
        }
    }
}
