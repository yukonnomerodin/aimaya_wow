using System.Globalization;
using System.Text.Json;

namespace Adapter.WorldGateway;

internal static class EnterEncryptedModeGoldenMetadataLoader
{
    public static bool TryBuildRetailEnterEncryptedModeFrameFromGoldenMetadata(
        string metadataPath,
        uint fallbackOpcode,
        out byte[] retailFrame,
        out uint retailOpcode,
        out string? error,
        out byte[] retailWorldEncryptKey32,
        out EnterEncryptedModeProof proof)
    {
        retailFrame = Array.Empty<byte>();
        retailOpcode = fallbackOpcode;
        error = null;
        retailWorldEncryptKey32 = Array.Empty<byte>();
        proof = default;

        if (string.IsNullOrWhiteSpace(metadataPath))
        {
            error = "Golden metadata path is empty.";
            return false;
        }

        string resolvedPath = metadataPath;
        if (!Path.IsPathRooted(resolvedPath))
        {
            resolvedPath = Path.Combine(WorldGatewayPathResolver.ResolveProjectRoot(), resolvedPath);
        }

        if (!File.Exists(resolvedPath))
        {
            error = $"Golden metadata file not found: {resolvedPath}";
            return false;
        }

        string payloadHex;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(resolvedPath));
            JsonElement root = doc.RootElement;

            if (root.TryGetProperty("opcode", out JsonElement opcodeElement))
            {
                string? opcodeText = opcodeElement.GetString();
                if (TryParseFlexibleUInt32(opcodeText, out uint parsedOpcode))
                {
                    retailOpcode = parsedOpcode;
                }
            }
            else if (root.TryGetProperty("retail_opcode", out JsonElement retailOpcodeElement))
            {
                string? opcodeText = retailOpcodeElement.GetString();
                if (TryParseFlexibleUInt32(opcodeText, out uint parsedOpcode))
                {
                    retailOpcode = parsedOpcode;
                }
            }

            if (!root.TryGetProperty("payload_hex", out JsonElement payloadElement))
            {
                error = $"payload_hex is missing in {resolvedPath}";
                return false;
            }

            payloadHex = payloadElement.GetString() ?? string.Empty;
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            error = ex.Message;
            return false;
        }

        if (string.IsNullOrWhiteSpace(payloadHex))
        {
            error = $"payload_hex is empty in {resolvedPath}";
            return false;
        }

        byte[] payload;
        try
        {
            payload = Convert.FromHexString(payloadHex.Trim());
        }
        catch (FormatException ex)
        {
            error = $"Invalid payload_hex in {resolvedPath}: {ex.Message}";
            return false;
        }

        retailFrame = RetailEnvelopeBuilder.BuildRetailWorldFrame(retailOpcode, payload);
        proof = new EnterEncryptedModeProof(
            TimestampUtc: DateTimeOffset.UtcNow.ToString("O"),
            RetailOpcode: retailOpcode,
            RegionGroup: 0,
            IncludeRegionGroup: false,
            Enabled: true,
            EnabledAsByte: false,
            SignatureFirst: false,
            PreferBnetKeyData: false,
            KeySource: $"golden:{resolvedPath}",
            WireFormat: "GoldenReplay",
            SessionKeySha256: string.Empty,
            BnetKeyDataSha256: null,
            BnetKeyDerivationError: null,
            RetailWorldEncryptKeySha256: null,
            RetailWorldEncryptKeyHex: null,
            LocalChallengeHex: string.Empty,
            ServerChallengeHex: string.Empty,
            ToSignHex: string.Empty,
            SignatureHex: string.Empty,
            PayloadHex: Convert.ToHexString(payload),
            PayloadBytes: payload.Length);
        return true;
    }

    private static bool TryParseFlexibleUInt32(string? value, out uint parsed)
    {
        parsed = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string input = value.Trim();
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return uint.TryParse(input.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed);
        }

        return uint.TryParse(input, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed);
    }
}
