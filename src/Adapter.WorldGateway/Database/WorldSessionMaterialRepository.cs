using System.Globalization;
using Microsoft.Extensions.Logging;
using MySqlConnector;

namespace Adapter.WorldGateway;

internal sealed class WorldSessionMaterialRepository
{
    private const string EnsureWorldSessionMaterialSql = """
        CREATE TABLE IF NOT EXISTS adapter_world_session_material (
            account_id INT UNSIGNED NOT NULL PRIMARY KEY,
            key_data VARBINARY(64) NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """;

    private readonly ILogger<WorldProxyListener> _logger;
    private readonly string _authDbConnectionString;
    private readonly int _expectedSessionKeyBytes;
    private readonly int _authDbReadMaxAttempts;
    private readonly int _authDbReadRetryBaseDelayMs;
    private readonly int _authDbSelectCommandTimeoutSeconds;
    private int _worldSessionMaterialTableEnsured;

    public WorldSessionMaterialRepository(
        ILogger<WorldProxyListener> logger,
        string authDbConnectionString,
        int expectedSessionKeyBytes,
        int maxReadAttempts,
        int retryBaseDelayMs,
        int selectCommandTimeoutSeconds)
    {
        _logger = logger;
        _authDbConnectionString = authDbConnectionString;
        _expectedSessionKeyBytes = expectedSessionKeyBytes;
        _authDbReadMaxAttempts = maxReadAttempts;
        _authDbReadRetryBaseDelayMs = retryBaseDelayMs;
        _authDbSelectCommandTimeoutSeconds = selectCommandTimeoutSeconds;
    }

    public async ValueTask<int?> TryReadLatestSessionMaterialAccountIdAsync(CancellationToken cancellationToken)
    {
        for (int attempt = 1; attempt <= _authDbReadMaxAttempts; attempt++)
        {
            try
            {
                return await TryReadLatestSessionMaterialAccountIdOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is MySqlException or IOException)
            {
                if (attempt >= _authDbReadMaxAttempts)
                {
                    throw;
                }

                int delayMs = _authDbReadRetryBaseDelayMs * attempt;
                _logger.LogWarning(
                    ex,
                    "[WorldProxy][DB-GATE] Latest account id read transient failure. Attempt={Attempt}/{MaxAttempts}, RetryDelayMs={RetryDelayMs}",
                    attempt,
                    _authDbReadMaxAttempts,
                    delayMs);
                await Task.Delay(delayMs, cancellationToken).ConfigureAwait(false);
            }
        }

        return null;
    }

    public async ValueTask<AcoreSessionMaterial?> TryReadSessionMaterialByAccountIdAsync(int accountId, CancellationToken cancellationToken)
    {
        for (int attempt = 1; attempt <= _authDbReadMaxAttempts; attempt++)
        {
            try
            {
                return await TryReadSessionMaterialByAccountIdOnceAsync(accountId, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is MySqlException or IOException)
            {
                if (attempt >= _authDbReadMaxAttempts)
                {
                    throw;
                }

                int delayMs = _authDbReadRetryBaseDelayMs * attempt;
                _logger.LogWarning(
                    ex,
                    "[WorldProxy][DB-GATE] Session material read transient failure. AccountId={AccountId}, Attempt={Attempt}/{MaxAttempts}, RetryDelayMs={RetryDelayMs}",
                    accountId,
                    attempt,
                    _authDbReadMaxAttempts,
                    delayMs);
                await Task.Delay(delayMs, cancellationToken).ConfigureAwait(false);
            }
        }

        return null;
    }

    private async ValueTask<int?> TryReadLatestSessionMaterialAccountIdOnceAsync(CancellationToken cancellationToken)
    {
        await using var connection = new MySqlConnection(_authDbConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await EnsureWorldSessionMaterialTableAsync(connection, cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT account_id
            FROM adapter_world_session_material
            ORDER BY updated_at DESC, account_id DESC
            LIMIT 1;
            """;
        command.CommandTimeout = _authDbSelectCommandTimeoutSeconds;

        object? scalar = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        if (scalar is null || scalar is DBNull)
        {
            return null;
        }

        try
        {
            int accountId = Convert.ToInt32(scalar, CultureInfo.InvariantCulture);
            return accountId > 0 ? accountId : null;
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            _logger.LogWarning(
                "[WorldProxy][DB-GATE] Failed to parse latest adapter_world_session_material account id. ValueType={ValueType}, Message={Message}",
                scalar.GetType().Name,
                ex.Message);
            return null;
        }
    }

    private async ValueTask<AcoreSessionMaterial?> TryReadSessionMaterialByAccountIdOnceAsync(int accountId, CancellationToken cancellationToken)
    {
        await using var connection = new MySqlConnection(_authDbConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await EnsureWorldSessionMaterialTableAsync(connection, cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT a.username, a.session_key, m.key_data, a.expansion, a.locked
            FROM account a
            LEFT JOIN adapter_world_session_material m ON m.account_id = a.id
            WHERE a.id = @id
            LIMIT 1;
            """;
        command.CommandTimeout = _authDbSelectCommandTimeoutSeconds;
        command.Parameters.AddWithValue("@id", accountId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            _logger.LogWarning(
                "[WorldProxy][BRIDGE] Strict session key lookup failed: account row not found. AccountId={AccountId}",
                accountId);
            return null;
        }

        string accountName = reader.IsDBNull(0)
            ? string.Empty
            : reader.GetString(0).Trim().ToUpperInvariant();

        if (string.IsNullOrWhiteSpace(accountName))
        {
            _logger.LogWarning(
                "[WorldProxy][BRIDGE] Strict session key lookup failed: username is empty. AccountId={AccountId}",
                accountId);
            return null;
        }

        object sessionValue = reader.GetValue(1);
        if (!WorldSessionMaterialParser.TryExtractSessionKey(sessionValue, _expectedSessionKeyBytes, out string reason))
        {
            _logger.LogWarning(
                "[WorldProxy][BRIDGE] Strict session key lookup failed: session_key unusable. AccountId={AccountId}, Reason={Reason}",
                accountId,
                reason);
            return null;
        }

        byte[] sessionKey = WorldSessionMaterialParser.ExtractSessionKey(sessionValue, _expectedSessionKeyBytes);

        byte[]? bnetKeyData64 = null;
        if (!reader.IsDBNull(2))
        {
            object bnetValue = reader.GetValue(2);
            if (WorldSessionMaterialParser.TryExtractBnetKeyData64(bnetValue, out string bnetReason))
            {
                bnetKeyData64 = WorldSessionMaterialParser.ExtractBnetKeyData64(bnetValue);
            }
            else
            {
                _logger.LogWarning(
                    "[WorldProxy][BRIDGE] session_key_bnet material unusable. AccountId={AccountId}, Reason={Reason}",
                    accountId,
                    bnetReason);
            }
        }

        byte expansion = 0;
        if (!reader.IsDBNull(3))
        {
            object expansionValue = reader.GetValue(3);
            try
            {
                expansion = Convert.ToByte(expansionValue, CultureInfo.InvariantCulture);
            }
            catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
            {
                _logger.LogWarning(
                    "[WorldProxy][DB-GATE] Failed to parse account expansion flag. AccountId={AccountId}, ValueType={ValueType}, Message={Message}",
                    accountId,
                    expansionValue.GetType().Name,
                    ex.Message);
            }
        }

        bool locked = false;
        if (!reader.IsDBNull(4))
        {
            object lockedValue = reader.GetValue(4);
            try
            {
                locked = Convert.ToInt32(lockedValue, CultureInfo.InvariantCulture) != 0;
            }
            catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
            {
                _logger.LogWarning(
                    "[WorldProxy][DB-GATE] Failed to parse account locked flag. AccountId={AccountId}, ValueType={ValueType}, Message={Message}",
                    accountId,
                    lockedValue.GetType().Name,
                    ex.Message);
            }
        }

        return new AcoreSessionMaterial(accountId, accountName, sessionKey, bnetKeyData64, expansion, locked);
    }

    private async ValueTask EnsureWorldSessionMaterialTableAsync(MySqlConnection connection, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _worldSessionMaterialTableEnsured) == 1)
        {
            return;
        }

        await using var command = connection.CreateCommand();
        command.CommandText = EnsureWorldSessionMaterialSql;
        command.CommandTimeout = 5;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        Volatile.Write(ref _worldSessionMaterialTableEnsured, 1);
    }
}
