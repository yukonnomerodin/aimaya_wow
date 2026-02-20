using System.ComponentModel.DataAnnotations;

namespace Adapter.AuthGateway;

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    [Required]
    public string ConnectionString { get; init; } = string.Empty;

    [Range(1, 2000)]
    public int MinimumPoolSize { get; init; } = 16;

    [Range(1, 5000)]
    public int MaximumPoolSize { get; init; } = 512;

    [Range(1, 120)]
    public int ConnectionTimeoutSeconds { get; init; } = 15;

    [Range(1, 300)]
    public int CommandTimeoutSeconds { get; init; } = 30;
}

