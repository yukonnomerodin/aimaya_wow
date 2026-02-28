namespace Adapter.WorldGateway;

internal static class WorldProxyServiceBoundaryContract
{
    public const string R6ServiceBoundaryV1 = "r6.service_boundary.v1";

    public static string ResolveConfiguredVersion(string? configuredValue, out bool valid)
    {
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            valid = true;
            return R6ServiceBoundaryV1;
        }

        string normalized = configuredValue.Trim().ToLowerInvariant();
        valid = string.Equals(normalized, R6ServiceBoundaryV1, StringComparison.Ordinal);
        return valid
            ? normalized
            : R6ServiceBoundaryV1;
    }
}
