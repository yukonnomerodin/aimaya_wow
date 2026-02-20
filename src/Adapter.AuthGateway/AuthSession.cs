using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Adapter.AuthGateway;

public enum AuthSessionState : byte
{
    Init = 0,
    Challenge = 1,
    Proof = 2,
    Authenticated = 3
}

public sealed class AuthSession : IDisposable
{
    private readonly object _sync = new();
    private bool _disposed;

    public AuthSession(uint connectionId)
    {
        ConnectionId = connectionId;
        LastActivityUtc = DateTime.UtcNow;
    }

    public uint ConnectionId { get; }
    public int AccountId { get; private set; }
    public string Username { get; private set; } = string.Empty;
    public AuthSessionState State { get; private set; } = AuthSessionState.Init;
    public DateTime LastActivityUtc { get; private set; }

    private byte[] _salt = Array.Empty<byte>();       // s
    private byte[] _verifier = Array.Empty<byte>();   // v
    private byte[] _serverPublicB = Array.Empty<byte>(); // B
    private byte[] _serverPrivateb = Array.Empty<byte>(); // b
    private byte[]? _clientPublicA;
    private byte[]? _clientProofM1;
    private byte[]? _sessionKey;

    public void InitializeChallenge(
        int accountId,
        string username,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> verifier,
        ReadOnlySpan<byte> serverPublicB,
        ReadOnlySpan<byte> serverPrivateb)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(accountId);
        ArgumentException.ThrowIfNullOrWhiteSpace(username);

        lock (_sync)
        {
            ThrowIfDisposed();

            AccountId = accountId;
            Username = username;
            ReplaceSensitiveBuffer(ref _salt, salt);
            ReplaceSensitiveBuffer(ref _verifier, verifier);
            ReplaceSensitiveBuffer(ref _serverPublicB, serverPublicB);
            ReplaceSensitiveBuffer(ref _serverPrivateb, serverPrivateb);
            ClearSensitiveNullableBuffer(ref _clientPublicA);
            ClearSensitiveNullableBuffer(ref _clientProofM1);
            ClearSensitiveNullableBuffer(ref _sessionKey);
            State = AuthSessionState.Challenge;
            LastActivityUtc = DateTime.UtcNow;
        }
    }

    public bool TryTransitionToProof(ReadOnlySpan<byte> clientPublicA, ReadOnlySpan<byte> clientProofM1)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (State != AuthSessionState.Challenge)
            {
                return false;
            }

            ReplaceSensitiveNullableBuffer(ref _clientPublicA, clientPublicA);
            ReplaceSensitiveNullableBuffer(ref _clientProofM1, clientProofM1);
            State = AuthSessionState.Proof;
            LastActivityUtc = DateTime.UtcNow;
            return true;
        }
    }

    public void MarkAuthenticated(ReadOnlySpan<byte> sessionKey)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            ReplaceSensitiveNullableBuffer(ref _sessionKey, sessionKey);
            State = AuthSessionState.Authenticated;
            LastActivityUtc = DateTime.UtcNow;
        }
    }

    public void Touch()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            LastActivityUtc = DateTime.UtcNow;
        }
    }

    public bool IsExpired(DateTime utcNow, TimeSpan ttl)
    {
        lock (_sync)
        {
            return utcNow - LastActivityUtc >= ttl;
        }
    }

    public bool TryCaptureSrpMaterial(out AuthSessionSrpMaterial material)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (State == AuthSessionState.Init ||
                _salt.Length == 0 ||
                _verifier.Length == 0 ||
                _serverPublicB.Length == 0 ||
                _serverPrivateb.Length == 0)
            {
                material = default;
                return false;
            }

            material = new AuthSessionSrpMaterial(
                AccountId,
                Username,
                (byte[])_salt.Clone(),
                (byte[])_verifier.Clone(),
                (byte[])_serverPrivateb.Clone(),
                (byte[])_serverPublicB.Clone());

            return true;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            ClearSensitiveBuffer(ref _salt);
            ClearSensitiveBuffer(ref _verifier);
            ClearSensitiveBuffer(ref _serverPublicB);
            ClearSensitiveBuffer(ref _serverPrivateb);
            ClearSensitiveNullableBuffer(ref _clientPublicA);
            ClearSensitiveNullableBuffer(ref _clientProofM1);
            ClearSensitiveNullableBuffer(ref _sessionKey);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private static void ReplaceSensitiveBuffer(ref byte[] target, ReadOnlySpan<byte> source)
    {
        if (target.Length > 0)
        {
            CryptographicOperations.ZeroMemory(target);
        }

        target = source.ToArray();
    }

    private static void ReplaceSensitiveNullableBuffer(ref byte[]? target, ReadOnlySpan<byte> source)
    {
        if (target is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(target);
        }

        target = source.ToArray();
    }

    private static void ClearSensitiveBuffer(ref byte[] buffer)
    {
        if (buffer.Length > 0)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        buffer = Array.Empty<byte>();
    }

    private static void ClearSensitiveNullableBuffer(ref byte[]? buffer)
    {
        if (buffer is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(buffer);
        }

        buffer = null;
    }
}

public readonly record struct AuthSessionSrpMaterial(
    int AccountId,
    string Username,
    byte[] Salt,
    byte[] Verifier,
    byte[] ServerPrivateb,
    byte[] ServerPublicB);

public sealed class AuthSessionOptions
{
    public const string SectionName = "AuthSession";

    [Range(5, 3600)]
    public int SessionTtlSeconds { get; init; } = 120;

    [Range(1, 600)]
    public int CleanupIntervalSeconds { get; init; } = 15;
}

public interface IAuthSessionManager
{
    AuthSession CreateOrReplace(
        uint connectionId,
        int accountId,
        string username,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> verifier,
        ReadOnlySpan<byte> serverPublicB,
        ReadOnlySpan<byte> serverPrivateb);

    bool TryGet(uint connectionId, out AuthSession session);
    bool Remove(uint connectionId);
    int CleanupStaleSessions();
}

public sealed class AuthSessionManager : IAuthSessionManager, IDisposable
{
    private readonly ConcurrentDictionary<uint, AuthSession> _sessions = new();
    private readonly ILogger<AuthSessionManager> _logger;
    private readonly TimeSpan _sessionTtl;
    private readonly Timer _cleanupTimer;
    private bool _disposed;

    public AuthSessionManager(
        ILogger<AuthSessionManager> logger,
        IOptions<AuthSessionOptions> options)
    {
        _logger = logger;

        var config = options.Value;
        _sessionTtl = TimeSpan.FromSeconds(config.SessionTtlSeconds);
        var cleanupInterval = TimeSpan.FromSeconds(config.CleanupIntervalSeconds);

        _cleanupTimer = new Timer(
            static state => ((AuthSessionManager)state!).OnCleanupTimer(),
            this,
            dueTime: cleanupInterval,
            period: cleanupInterval);
    }

    public AuthSession CreateOrReplace(
        uint connectionId,
        int accountId,
        string username,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> verifier,
        ReadOnlySpan<byte> serverPublicB,
        ReadOnlySpan<byte> serverPrivateb)
    {
        ThrowIfDisposed();

        while (true)
        {
            if (_sessions.TryGetValue(connectionId, out AuthSession? existing))
            {
                var replacement = new AuthSession(connectionId);
                replacement.InitializeChallenge(accountId, username, salt, verifier, serverPublicB, serverPrivateb);

                if (_sessions.TryUpdate(connectionId, replacement, existing))
                {
                    existing.Dispose();
                    return replacement;
                }

                replacement.Dispose();
                continue;
            }

            var session = new AuthSession(connectionId);
            session.InitializeChallenge(accountId, username, salt, verifier, serverPublicB, serverPrivateb);
            if (_sessions.TryAdd(connectionId, session))
            {
                return session;
            }

            session.Dispose();
        }
    }

    public bool TryGet(uint connectionId, out AuthSession session)
    {
        ThrowIfDisposed();
        return _sessions.TryGetValue(connectionId, out session!);
    }

    public bool Remove(uint connectionId)
    {
        ThrowIfDisposed();

        if (_sessions.TryRemove(connectionId, out AuthSession? session))
        {
            session.Dispose();
            return true;
        }

        return false;
    }

    public int CleanupStaleSessions()
    {
        ThrowIfDisposed();

        int removed = 0;
        DateTime now = DateTime.UtcNow;

        foreach (KeyValuePair<uint, AuthSession> pair in _sessions)
        {
            if (!pair.Value.IsExpired(now, _sessionTtl))
            {
                continue;
            }

            if (_sessions.TryRemove(pair.Key, out AuthSession? stale))
            {
                stale.Dispose();
                removed++;
            }
        }

        return removed;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cleanupTimer.Dispose();

        foreach (KeyValuePair<uint, AuthSession> pair in _sessions)
        {
            if (_sessions.TryRemove(pair.Key, out AuthSession? session))
            {
                session.Dispose();
            }
        }
    }

    private void OnCleanupTimer()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            int removed = CleanupStaleSessions();
            if (removed > 0)
            {
                _logger.LogDebug("AuthSession cleanup removed {Removed} stale sessions.", removed);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AuthSession cleanup failed.");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
