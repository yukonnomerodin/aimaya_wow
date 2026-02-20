using Dapper;
using MySqlConnector;

namespace Adapter.AuthGateway.Database;

public interface IDatabaseService
{
    ValueTask<AccountData?> GetAccountData(string username, CancellationToken cancellationToken = default);
    ValueTask<bool> UpdateSessionKey(int accountId, byte[] newKey, CancellationToken cancellationToken = default);
    ValueTask<IReadOnlyList<RealmData>> GetWorldList(CancellationToken cancellationToken = default);
}

public sealed class DatabaseService : IDatabaseService
{
    private const int SessionKeyLength = 40; // AzerothCore AuthDefines.h

    private const string GetAccountSql = """
        SELECT
            id AS Id,
            username AS Username,
            salt AS Salt,
            verifier AS Verifier,
            session_key AS SessionKey
        FROM account
        WHERE username = @username
        LIMIT 1;
        """;

    private const string UpdateSessionKeySql = """
        UPDATE account
        SET session_key = CAST(@sessionKey AS BINARY(40))
        WHERE id = @accountId;
        """;

    private const string GetWorldListSql = """
        SELECT
            id AS Id,
            name AS Name,
            address AS Address,
            localAddress AS LocalAddress,
            localSubnetMask AS LocalSubnetMask,
            port AS Port,
            icon AS Icon,
            flag AS Flag,
            timezone AS Timezone,
            allowedSecurityLevel AS AllowedSecurityLevel,
            population AS Population,
            gamebuild AS Gamebuild,
            1 AS Region,
            1 AS Battlegroup
        FROM realmlist
        WHERE flag <> 3
        ORDER BY name;
        """;

    private readonly MySqlDataSource _dataSource;

    public DatabaseService(MySqlDataSource dataSource)
    {
        _dataSource = dataSource ?? throw new ArgumentNullException(nameof(dataSource));
    }

    public async ValueTask<AccountData?> GetAccountData(string username, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        // AzerothCore stores username normalized in uppercase-latin semantics.
        // Keep normalization policy explicit at gateway boundary.
        string normalized = username.Trim().ToUpperInvariant();

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var command = new CommandDefinition(
            commandText: GetAccountSql,
            parameters: new { username = normalized },
            cancellationToken: cancellationToken);

        return await connection.QuerySingleOrDefaultAsync<AccountData>(command).ConfigureAwait(false);
    }

    public async ValueTask<bool> UpdateSessionKey(int accountId, byte[] newKey, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(accountId);
        ArgumentNullException.ThrowIfNull(newKey);

        if (newKey.Length != SessionKeyLength)
        {
            throw new ArgumentException(
                $"Session key must be exactly {SessionKeyLength} bytes for AzerothCore auth schema.",
                nameof(newKey));
        }

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var command = new CommandDefinition(
            commandText: UpdateSessionKeySql,
            parameters: new { accountId, sessionKey = newKey },
            cancellationToken: cancellationToken);

        var affected = await connection.ExecuteAsync(command).ConfigureAwait(false);
        return affected == 1;
    }

    public async ValueTask<IReadOnlyList<RealmData>> GetWorldList(CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var command = new CommandDefinition(
            commandText: GetWorldListSql,
            cancellationToken: cancellationToken);

        var rows = await connection.QueryAsync<RealmData>(command).ConfigureAwait(false);
        return rows.AsList();
    }
}

public sealed record AccountData(
    int Id,
    string Username,
    byte[] Salt,
    byte[] Verifier,
    byte[]? SessionKey);

public sealed class RealmData
{
    public uint Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string LocalAddress { get; set; } = string.Empty;
    public string LocalSubnetMask { get; set; } = string.Empty;
    public ushort Port { get; set; }
    public byte Icon { get; set; }
    public byte Flag { get; set; }
    public byte Timezone { get; set; }
    public byte AllowedSecurityLevel { get; set; }
    public float Population { get; set; }
    public uint Gamebuild { get; set; }
    public byte Region { get; set; }
    public byte Battlegroup { get; set; }
}
