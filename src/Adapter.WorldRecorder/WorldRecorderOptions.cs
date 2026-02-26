using System.ComponentModel.DataAnnotations;

namespace Adapter.WorldRecorder;

public sealed class WorldRecorderOptions
{
    public const string SectionName = "WorldRecorder";

    public string ListenAddress { get; init; } = "0.0.0.0";

    [Range(1, 65535)]
    public int ListenPort { get; init; } = 8087;

    [Range(1, 8192)]
    public int Backlog { get; init; } = 1024;

    public string UpstreamAddress { get; init; } = "127.0.0.1";

    [Range(1, 65535)]
    public int UpstreamPort { get; init; } = 8088;

    [Range(100, 60000)]
    public int UpstreamConnectTimeoutMs { get; init; } = 3000;

    [Range(1024, 1024 * 1024)]
    public int RelayBufferBytes { get; init; } = 64 * 1024;

    [Range(1024, 8 * 1024 * 1024)]
    public int MaxFrameBytes { get; init; } = 256 * 1024;

    [Range(16, 4096)]
    public int MaxFrameEvents { get; init; } = 256;

    public bool EnableRawCapture { get; init; } = true;

    public bool EnablePerFrameLogs { get; init; } = true;

    public string RunlogsRootPath { get; init; } = "docs/handshake/runlogs";

    public string[] EnterEncryptedOpcodeHints { get; init; } =
    [
        "0x00490004",
        "0x00490003",
        "0x00490005",
        "0x00420004",
        "0x00420005"
    ];
}
