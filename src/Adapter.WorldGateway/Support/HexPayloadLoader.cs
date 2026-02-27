using System.Text;

namespace Adapter.WorldGateway;

internal static class HexPayloadLoader
{
    public static bool TryLoadHexPayloadFromFile(
        string rawPath,
        out byte[] payload,
        out string? error,
        out string? resolvedPath)
    {
        return TryLoadHexPayloadFromFile(rawPath, WorldGatewayPathResolver.ResolveProjectRoot(), out payload, out error, out resolvedPath);
    }

    public static bool TryLoadHexPayloadFromFile(
        string rawPath,
        string projectRoot,
        out byte[] payload,
        out string? error,
        out string? resolvedPath)
    {
        payload = Array.Empty<byte>();
        error = null;
        resolvedPath = null;

        if (string.IsNullOrWhiteSpace(rawPath))
        {
            error = "empty payload path";
            return false;
        }

        resolvedPath = Path.IsPathRooted(rawPath)
            ? rawPath
            : Path.Combine(projectRoot, rawPath);

        if (!File.Exists(resolvedPath))
        {
            error = "payload file not found";
            return false;
        }

        string text;
        try
        {
            text = File.ReadAllText(resolvedPath, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            error = $"failed to read payload file: {ex.Message}";
            return false;
        }

        return TryParseHexPayload(text, resolvedPath, out payload, out error);
    }

    public static bool TryParseFixedLengthHex(string rawValue, int expectedLengthBytes, out byte[] bytes, out string? error)
    {
        bytes = Array.Empty<byte>();
        error = null;

        if (string.IsNullOrWhiteSpace(rawValue))
        {
            error = "empty hex value";
            return false;
        }

        string normalized = rawValue.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != expectedLengthBytes * 2)
        {
            error = $"expected {expectedLengthBytes * 2} hex chars but got {normalized.Length}";
            return false;
        }

        if (!IsHex(normalized))
        {
            error = "non-hex characters detected";
            return false;
        }

        try
        {
            bytes = Convert.FromHexString(normalized);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryParseHexPayload(string rawHex, string sourcePath, out byte[] payload, out string? error)
    {
        payload = Array.Empty<byte>();
        error = null;

        if (string.IsNullOrWhiteSpace(rawHex))
        {
            error = $"Hex payload is empty in {sourcePath}";
            return false;
        }

        string normalized = new string(rawHex.Where(static c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length == 0)
        {
            error = $"Hex payload is empty after trim in {sourcePath}";
            return false;
        }

        if ((normalized.Length & 1) != 0)
        {
            error = $"Hex payload length must be even in {sourcePath}. Length={normalized.Length}";
            return false;
        }

        if (!IsHex(normalized))
        {
            error = $"Hex payload contains invalid characters in {sourcePath}";
            return false;
        }

        try
        {
            payload = Convert.FromHexString(normalized);
            if (payload.Length == 0)
            {
                error = "payload parsed as zero bytes";
                return false;
            }

            return true;
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static bool IsHex(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char ch = value[i];
            bool isHexDigit =
                (ch >= '0' && ch <= '9') ||
                (ch >= 'a' && ch <= 'f') ||
                (ch >= 'A' && ch <= 'F');
            if (!isHexDigit)
            {
                return false;
            }
        }

        return true;
    }
}
