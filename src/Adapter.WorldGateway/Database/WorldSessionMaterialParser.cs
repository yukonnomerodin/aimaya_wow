using System.Security.Cryptography;

namespace Adapter.WorldGateway;

internal static class WorldSessionMaterialParser
{
    public static bool TryExtractSessionKey(object value, int expectedLengthBytes, out string reason)
    {
        reason = string.Empty;

        if (value is DBNull)
        {
            reason = "NULL";
            return false;
        }

        if (value is byte[] raw)
        {
            if (raw.Length >= expectedLengthBytes)
            {
                return true;
            }

            reason = $"byte[{raw.Length}]";
            return false;
        }

        if (value is string s)
        {
            string text = s.Trim();
            if (text.Length == expectedLengthBytes * 2 && HexPayloadLoader.IsHex(text))
            {
                return true;
            }

            reason = $"string[{text.Length}]";
            return false;
        }

        reason = value.GetType().FullName ?? value.GetType().Name;
        return false;
    }

    public static byte[] ExtractSessionKey(object value, int expectedLengthBytes)
    {
        if (value is byte[] raw)
        {
            if (raw.Length == expectedLengthBytes)
            {
                return raw;
            }

            byte[] trimmed = GC.AllocateUninitializedArray<byte>(expectedLengthBytes);
            raw.AsSpan(0, expectedLengthBytes).CopyTo(trimmed);
            CryptographicOperations.ZeroMemory(raw);
            return trimmed;
        }

        if (value is string s)
        {
            byte[] parsed = Convert.FromHexString(s.Trim());
            if (parsed.Length == expectedLengthBytes)
            {
                return parsed;
            }

            byte[] trimmed = GC.AllocateUninitializedArray<byte>(expectedLengthBytes);
            parsed.AsSpan(0, expectedLengthBytes).CopyTo(trimmed);
            CryptographicOperations.ZeroMemory(parsed);
            return trimmed;
        }

        throw new InvalidOperationException($"Unsupported session_key value type: {value.GetType().FullName}");
    }

    public static bool TryExtractBnetKeyData64(object value, out string reason)
    {
        reason = string.Empty;

        if (value is DBNull)
        {
            reason = "NULL";
            return false;
        }

        if (value is byte[] raw)
        {
            if (raw.Length == 64)
            {
                return true;
            }

            reason = $"byte[{raw.Length}]";
            return false;
        }

        if (value is string s)
        {
            string text = s.Trim();
            if (text.Length == 128 && HexPayloadLoader.IsHex(text))
            {
                return true;
            }

            reason = $"string[{text.Length}]";
            return false;
        }

        reason = value.GetType().FullName ?? value.GetType().Name;
        return false;
    }

    public static byte[] ExtractBnetKeyData64(object value)
    {
        if (value is byte[] raw)
        {
            if (raw.Length == 64)
            {
                return raw;
            }

            throw new InvalidOperationException($"Unexpected key_data byte length: {raw.Length}.");
        }

        if (value is string s)
        {
            byte[] parsed = Convert.FromHexString(s.Trim());
            if (parsed.Length == 64)
            {
                return parsed;
            }

            throw new InvalidOperationException($"Unexpected key_data hex length: {parsed.Length} bytes.");
        }

        throw new InvalidOperationException($"Unsupported key_data value type: {value.GetType().FullName}");
    }
}
