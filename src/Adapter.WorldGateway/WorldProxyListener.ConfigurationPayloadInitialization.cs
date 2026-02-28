namespace Adapter.WorldGateway;

public sealed partial class WorldProxyListener
{
    private readonly record struct ProbeFixedHexPayloadLoadResult(
        bool Provided,
        bool Valid,
        byte[] Payload,
        string? Error);

    private readonly record struct ProbeFileHexPayloadLoadResult(
        bool Provided,
        bool Valid,
        byte[] Payload,
        string? Error,
        string? ResolvedPath);

    private static ProbeFixedHexPayloadLoadResult LoadOptionalFixedLengthHexPayload(
        string? configuredValue,
        int expectedLengthBytes,
        byte[] defaultPayload)
    {
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            return new ProbeFixedHexPayloadLoadResult(
                Provided: false,
                Valid: false,
                Payload: defaultPayload,
                Error: null);
        }

        bool valid = HexPayloadLoader.TryParseFixedLengthHex(
            configuredValue,
            expectedLengthBytes,
            out byte[] parsedPayload,
            out string? parseError);
        if (valid)
        {
            return new ProbeFixedHexPayloadLoadResult(
                Provided: true,
                Valid: true,
                Payload: parsedPayload,
                Error: null);
        }

        return new ProbeFixedHexPayloadLoadResult(
            Provided: true,
            Valid: false,
            Payload: defaultPayload,
            Error: parseError);
    }

    private static ProbeFileHexPayloadLoadResult LoadOptionalFileHexPayload(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return new ProbeFileHexPayloadLoadResult(
                Provided: false,
                Valid: false,
                Payload: [],
                Error: null,
                ResolvedPath: null);
        }

        bool valid = HexPayloadLoader.TryLoadHexPayloadFromFile(
            configuredPath,
            out byte[] parsedPayload,
            out string? parseError,
            out string? resolvedPath);
        return new ProbeFileHexPayloadLoadResult(
            Provided: true,
            Valid: valid,
            Payload: valid ? parsedPayload : [],
            Error: valid ? null : parseError,
            ResolvedPath: resolvedPath);
    }
}
