using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Adapter.AuthGateway;

public interface IAuthOpcodeManager
{
    bool TryGetOpcode(string packetName, out uint opcode);
}

public sealed class AuthOpcodeOptions
{
    public const string SectionName = "AuthOpcodes";

    [Required]
    public string FilePath { get; init; } = "opcodes.json";
}

public sealed class AuthOpcodeManager : IAuthOpcodeManager
{
    private readonly ILogger<AuthOpcodeManager> _logger;
    private readonly Dictionary<string, uint> _nameToOpcode;

    public AuthOpcodeManager(
        ILogger<AuthOpcodeManager> logger,
        IHostEnvironment hostEnvironment,
        IOptions<AuthOpcodeOptions> options)
    {
        _logger = logger;
        _nameToOpcode = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);

        string configuredPath = options.Value.FilePath.Trim();
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            _logger.LogWarning("Auth opcode source path is empty. All opcode bindings will be disabled.");
            return;
        }

        string fullPath = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.Combine(hostEnvironment.ContentRootPath, configuredPath);

        if (!File.Exists(fullPath))
        {
            _logger.LogWarning("Opcode map file not found: {Path}. All opcode bindings will be disabled.", fullPath);
            return;
        }

        try
        {
            using FileStream stream = File.OpenRead(fullPath);
            Dictionary<string, uint>? parsed = JsonSerializer.Deserialize<Dictionary<string, uint>>(stream);
            if (parsed is null || parsed.Count == 0)
            {
                _logger.LogWarning("Opcode map file is empty: {Path}.", fullPath);
                return;
            }

            foreach (KeyValuePair<string, uint> pair in parsed)
            {
                if (string.IsNullOrWhiteSpace(pair.Key))
                {
                    continue;
                }

                _nameToOpcode[pair.Key.Trim()] = pair.Value;
            }

            _logger.LogInformation("Loaded {Count} auth opcodes from {Path}.", _nameToOpcode.Count, fullPath);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse opcode map JSON: {Path}", fullPath);
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Failed to read opcode map file: {Path}", fullPath);
        }
    }

    public bool TryGetOpcode(string packetName, out uint opcode)
    {
        if (string.IsNullOrWhiteSpace(packetName))
        {
            opcode = 0;
            return false;
        }

        return _nameToOpcode.TryGetValue(packetName, out opcode);
    }
}
