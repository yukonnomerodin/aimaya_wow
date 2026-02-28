using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;

namespace Adapter.WorldGateway.IntegrationTests;

public sealed class GatewaySmokeFixture : IDisposable
{
    private const int ScriptTimeoutMs = 120000;
    private const int PortReadyTimeoutMs = 60000;
    private readonly string _repoRoot;

    public GatewaySmokeFixture()
    {
        _repoRoot = ResolveRepoRoot();
        HypothesisId = "M2-R5-INTEGRATION-HANDSHAKE-RELAY-SMOKE-103";
        IsEnabled = string.Equals(
            Environment.GetEnvironmentVariable("WORLDGW_ENABLE_INTEGRATION_SMOKE"),
            "1",
            StringComparison.Ordinal);

        if (!OperatingSystem.IsWindows() || !IsEnabled)
        {
            return;
        }

        if (!TryCollectSmokeData(out string probeOutput, out string validationOutput))
        {
            RunScript("scripts/start_retail_gateways.ps1", $"-HypothesisId {HypothesisId}");
            WaitForTcpPort("127.0.0.1", 8086, PortReadyTimeoutMs);

            probeOutput = RunScriptWithRetries(
                "scripts/invoke_synthetic_world_probe.ps1",
                "-AccountId 1",
                retryCount: 8,
                retryDelayMs: 1000);

            validationOutput = RunScriptWithRetries(
                "scripts/validate_latest_handshake_run.ps1",
                $"-HypothesisId {HypothesisId}",
                retryCount: 8,
                retryDelayMs: 900,
                shouldRetry: output =>
                    output.Contains("\"run_valid\": false", StringComparison.OrdinalIgnoreCase) ||
                    output.Contains("\"report_path\": null", StringComparison.OrdinalIgnoreCase));
        }

        ProbeJson = JsonDocument.Parse(ExtractJson(probeOutput));
        ValidationJson = JsonDocument.Parse(ExtractJson(validationOutput));
    }

    public string HypothesisId { get; }

    public bool IsEnabled { get; }

    public JsonDocument? ProbeJson { get; }

    public JsonDocument? ValidationJson { get; }

    public void Dispose()
    {
        ProbeJson?.Dispose();
        ValidationJson?.Dispose();
    }

    private string RunScript(string relativeScriptPath, string arguments)
    {
        string scriptPath = Path.Combine(_repoRoot, relativeScriptPath);
        if (!File.Exists(scriptPath))
        {
            throw new FileNotFoundException("Script was not found.", scriptPath);
        }

        var psi = new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\" {arguments}",
            WorkingDirectory = _repoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start script: {scriptPath}");
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(ScriptTimeoutMs))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"Script timeout after {ScriptTimeoutMs}ms: {relativeScriptPath}");
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Script failed: {relativeScriptPath}{Environment.NewLine}ExitCode={process.ExitCode}{Environment.NewLine}STDOUT:{Environment.NewLine}{stdout}{Environment.NewLine}STDERR:{Environment.NewLine}{stderr}");
        }

        return stdout;
    }

    private string RunScriptWithRetries(
        string relativeScriptPath,
        string arguments,
        int retryCount,
        int retryDelayMs,
        Func<string, bool>? shouldRetry = null)
    {
        Exception? lastError = null;
        for (int attempt = 1; attempt <= retryCount; attempt++)
        {
            try
            {
                string output = RunScript(relativeScriptPath, arguments);
                if (shouldRetry is null || !shouldRetry(output))
                {
                    return output;
                }
            }
            catch (InvalidOperationException ex)
            {
                lastError = ex;
            }

            Thread.Sleep(retryDelayMs);
        }

        if (lastError is not null)
        {
            throw lastError;
        }

        throw new InvalidOperationException($"Script did not produce a successful result after {retryCount} attempts: {relativeScriptPath}");
    }

    private bool TryCollectSmokeData(out string probeOutput, out string validationOutput)
    {
        probeOutput = string.Empty;
        validationOutput = string.Empty;

        try
        {
            probeOutput = RunScriptWithRetries(
                "scripts/invoke_synthetic_world_probe.ps1",
                "-AccountId 1",
                retryCount: 3,
                retryDelayMs: 600);
            validationOutput = RunScriptWithRetries(
                "scripts/validate_latest_handshake_run.ps1",
                $"-HypothesisId {HypothesisId}",
                retryCount: 3,
                retryDelayMs: 500,
                shouldRetry: output =>
                    output.Contains("\"run_valid\": false", StringComparison.OrdinalIgnoreCase) ||
                    output.Contains("\"report_path\": null", StringComparison.OrdinalIgnoreCase));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string ResolveRepoRoot()
    {
        string current = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(current))
        {
            if (File.Exists(Path.Combine(current, "aimaya_wow.sln")))
            {
                return current;
            }

            string? parent = Directory.GetParent(current)?.FullName;
            if (string.IsNullOrWhiteSpace(parent) || string.Equals(parent, current, StringComparison.Ordinal))
            {
                break;
            }

            current = parent;
        }

        throw new DirectoryNotFoundException("Repository root with aimaya_wow.sln was not found.");
    }

    private static string ExtractJson(string text)
    {
        int start = text.IndexOf('{');
        int end = text.LastIndexOf('}');
        if (start < 0 || end <= start)
        {
            throw new InvalidDataException($"JSON payload was not found in script output: {text}");
        }

        return text[start..(end + 1)];
    }

    private static void WaitForTcpPort(string host, int port, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            using var client = new TcpClient();
            try
            {
                var connectTask = client.ConnectAsync(host, port);
                if (connectTask.Wait(500) && client.Connected)
                {
                    return;
                }
            }
            catch (SocketException)
            {
                // Readiness probe loop: socket may be unavailable during restart window.
            }

            Thread.Sleep(250);
        }

        throw new TimeoutException($"Port {host}:{port} did not become ready in {timeoutMs}ms.");
    }
}
