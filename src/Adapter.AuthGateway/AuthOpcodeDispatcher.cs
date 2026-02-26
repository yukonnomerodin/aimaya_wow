using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Adapter.AuthGateway.Database;
using Microsoft.Extensions.Logging;

namespace Adapter.AuthGateway;

public enum AuthDispatchResult : byte
{
    Continue = 0,
    Disconnect = 1
}

public interface IAuthOpcodeDispatcher
{
    ValueTask<AuthDispatchResult> DispatchAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken);

    bool IsKnownRoute(uint serviceId, uint serviceHash, uint methodId);
}

public interface IAuthHandler
{
    ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken);
}

public interface IBnetHandler
{
    ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken);
}

public static class BnetServiceHashes
{
    // TrinityCore connection_service.pb.h
    public const uint ConnectionOriginal = 0x65446991;
    public const uint ConnectionName = 0x2782094B;

    // TrinityCore authentication_service.pb.h
    public const uint AuthenticationListenerOriginal = 0x71240E35;
    public const uint AuthenticationListenerName = 0x4DA86228;
    public const uint AuthenticationServiceOriginal = 0x0DECFC01;
    public const uint AuthenticationServiceName = 0xFF5A6AC3;

    // TrinityCore account_service.pb.h
    public const uint AccountServiceOriginal = 0x62DA0891;
    public const uint AccountServiceName = 0x1E4DC42F;

    // TrinityCore game_utilities_service.pb.h
    public const uint GameUtilitiesServiceOriginal = 0x3FC1274D;
    public const uint GameUtilitiesServiceName = 0x51923A28;
}

internal static class BnetContextKeys
{
    public const string AccountId = "bnet.accountId";
    public const string GameAccountName = "bnet.gameAccountName";
    public const string ClientPlatformFourCc = "bnet.clientPlatformFourCc";
    public const string ClientArchFourCc = "bnet.clientArchFourCc";
    public const string ClientTypeFourCc = "bnet.clientTypeFourCc";
    public const string ClientSecret32 = "bnet.clientSecret32";
}

/// <summary>
/// Retail 12.0.1 auth opcodes MUST be handled as uint.
/// </summary>
public static class Retail1201AuthOpcodes
{
    public const string CmsgAuthSessionName = "CMSG_AUTH_SESSION";
    public const string CmsgAuthContinuedSessionName = "CMSG_AUTH_CONTINUED_SESSION";
    public const string CmsgBattleNetRequestName = "CMSG_BATTLENET_REQUEST";
    public const string CmsgBattleNetChallengeResponseName = "CMSG_BATTLENET_CHALLENGE_RESPONSE";
    public const string CmsgRealmListRequestName = "CMSG_REALM_LIST_REQUEST";
    public const string CmsgEnumCharactersInAuthName = "CMSG_ENUM_CHARACTERS_IN_AUTH";

    public const uint SmsgAuthChallenge = 0xC10001;
    public const uint SmsgAuthResponse = 0xC10002;
    public const uint SmsgRealmList = 0xC10003;
}

internal enum BridgeAuthStatus : byte
{
    Success = 0,
    UnknownAccount = 4,
    InvalidProof = 6,
    InternalError = 8
}

public sealed class AuthOpcodeDispatcher : IAuthOpcodeDispatcher
{
    private readonly ILogger<AuthOpcodeDispatcher> _logger;
    private readonly Dictionary<(uint ServiceHash, uint MethodId), IBnetHandler> _hashHandlers;
    private readonly Dictionary<(uint ServiceHash, uint MethodId), string> _hashRouteNames;
    private readonly Dictionary<(uint ServiceId, uint MethodId), IBnetHandler> _legacyHandlers;
    private readonly Dictionary<(uint ServiceId, uint MethodId), string> _legacyRouteNames;

    public AuthOpcodeDispatcher(
        ILogger<AuthOpcodeDispatcher> logger,
        BnetConnectionHandler bnetConnectionHandler,
        BnetBindHandler bnetBindHandler,
        BnetKeepAliveHandler bnetKeepAliveHandler,
        BnetConnectionControlHandler bnetConnectionControlHandler,
        BnetAuthenticationLogonHandler bnetAuthenticationLogonHandler,
        BnetAccountHandler bnetAccountHandler,
        BnetGameUtilitiesHandler bnetGameUtilitiesHandler)
    {
        _logger = logger;

        _hashHandlers = new Dictionary<(uint ServiceHash, uint MethodId), IBnetHandler>(capacity: 16);
        _hashRouteNames = new Dictionary<(uint ServiceHash, uint MethodId), string>(capacity: 16);
        _legacyHandlers = new Dictionary<(uint ServiceId, uint MethodId), IBnetHandler>(capacity: 8);
        _legacyRouteNames = new Dictionary<(uint ServiceId, uint MethodId), string>(capacity: 8);

        // connection_service.pb.h (TrinityCore): hash 0x65446991 (original), 0x2782094B (name)
        RegisterHashedRoute(BnetServiceHashes.ConnectionOriginal, 1, "bnet.protocol.connection.ConnectRequest", bnetConnectionHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionOriginal, 2, "bnet.protocol.connection.BindRequest", bnetBindHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionOriginal, 5, "bnet.protocol.connection.KeepAlive", bnetKeepAliveHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionOriginal, 6, "bnet.protocol.connection.Encrypt", bnetConnectionControlHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionOriginal, 7, "bnet.protocol.connection.RequestDisconnect", bnetConnectionControlHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionName, 1, "bnet.protocol.connection.ConnectRequest", bnetConnectionHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionName, 2, "bnet.protocol.connection.BindRequest", bnetBindHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionName, 5, "bnet.protocol.connection.KeepAlive", bnetKeepAliveHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionName, 6, "bnet.protocol.connection.Encrypt", bnetConnectionControlHandler);
        RegisterHashedRoute(BnetServiceHashes.ConnectionName, 7, "bnet.protocol.connection.RequestDisconnect", bnetConnectionControlHandler);

        // bnet.protocol.authentication.AuthenticationService.Logon
        RegisterHashedRoute(BnetServiceHashes.AuthenticationServiceOriginal, 1, "bnet.protocol.authentication.AuthenticationService.Logon", bnetAuthenticationLogonHandler);
        RegisterHashedRoute(BnetServiceHashes.AuthenticationServiceName, 1, "bnet.protocol.authentication.AuthenticationService.Logon", bnetAuthenticationLogonHandler);

        // bnet.protocol.account.AccountService
        RegisterHashedRoute(BnetServiceHashes.AccountServiceOriginal, 30, "bnet.protocol.account.AccountService.GetAccountState", bnetAccountHandler);
        RegisterHashedRoute(BnetServiceHashes.AccountServiceOriginal, 31, "bnet.protocol.account.AccountService.GetGameAccountState", bnetAccountHandler);
        RegisterHashedRoute(BnetServiceHashes.AccountServiceName, 30, "bnet.protocol.account.AccountService.GetAccountState", bnetAccountHandler);
        RegisterHashedRoute(BnetServiceHashes.AccountServiceName, 31, "bnet.protocol.account.AccountService.GetGameAccountState", bnetAccountHandler);

        // bnet.protocol.game_utilities.GameUtilitiesService
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceOriginal, 1, "bnet.protocol.game_utilities.GameUtilitiesService.ProcessClientRequest", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceOriginal, 10, "bnet.protocol.game_utilities.GameUtilitiesService.GetAllValuesForAttribute", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceOriginal, 11, "bnet.protocol.game_utilities.GameUtilitiesService.RegisterUtilities", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceOriginal, 12, "bnet.protocol.game_utilities.GameUtilitiesService.UnregisterUtilities", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceName, 1, "bnet.protocol.game_utilities.GameUtilitiesService.ProcessClientRequest", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceName, 10, "bnet.protocol.game_utilities.GameUtilitiesService.GetAllValuesForAttribute", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceName, 11, "bnet.protocol.game_utilities.GameUtilitiesService.RegisterUtilities", bnetGameUtilitiesHandler);
        RegisterHashedRoute(BnetServiceHashes.GameUtilitiesServiceName, 12, "bnet.protocol.game_utilities.GameUtilitiesService.UnregisterUtilities", bnetGameUtilitiesHandler);

        // Compatibility route for transitional dumps with service_id-only envelopes.
        RegisterLegacyRoute(0, 1, "bnet.protocol.connection.ConnectRequest (legacy)", bnetConnectionHandler);
        RegisterLegacyRoute(0, 2, "bnet.protocol.connection.BindRequest (legacy)", bnetBindHandler);
        RegisterLegacyRoute(0, 5, "bnet.protocol.connection.KeepAlive (legacy)", bnetKeepAliveHandler);
        RegisterLegacyRoute(0, 6, "bnet.protocol.connection.Encrypt (legacy)", bnetConnectionControlHandler);
        RegisterLegacyRoute(0, 7, "bnet.protocol.connection.RequestDisconnect (legacy)", bnetConnectionControlHandler);
    }

    public async ValueTask<AuthDispatchResult> DispatchAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        uint normalizedMethodId = methodId & 0x3FFFFFFFu;

        if (TryResolveRoute(
                serviceId,
                serviceHash,
                normalizedMethodId,
                out IBnetHandler handler,
                out string routeName))
        {
            _logger.LogInformation(
                "[BNET ROUTE] {Name} ServiceId={ServiceId} ServiceHash=0x{ServiceHash:X8} MethodId={MethodId} MethodIdRaw=0x{MethodIdRaw:X8} Token={Token} ConnectionId={ConnectionId} PayloadBytes={PayloadBytes}",
                routeName,
                serviceId,
                serviceHash,
                normalizedMethodId,
                methodId,
                token,
                context.ConnectionId,
                payload.Length);

            return await handler
                .HandleAsync(context, serviceId, serviceHash, normalizedMethodId, token, payload, cancellationToken)
                .ConfigureAwait(false);
        }

        _logger.LogInformation(
            "[UNKNOWN BNET METHOD] ServiceId={ServiceId} ServiceHash=0x{ServiceHash:X8} MethodId={MethodId} MethodIdRaw=0x{MethodIdRaw:X8} Token={Token} ConnectionId={ConnectionId} Remote={Remote} PayloadBytes={PayloadBytes}",
            serviceId,
            serviceHash,
            normalizedMethodId,
            methodId,
            token,
            context.ConnectionId,
            context.RemoteEndpoint,
            payload.Length);

        return AuthDispatchResult.Continue;
    }

    public bool IsKnownRoute(uint serviceId, uint serviceHash, uint methodId)
    {
        uint normalizedMethodId = methodId & 0x3FFFFFFFu;
        return _hashHandlers.ContainsKey((serviceHash, normalizedMethodId))
               || _legacyHandlers.ContainsKey((serviceId, normalizedMethodId));
    }

    private void RegisterHashedRoute(uint serviceHash, uint methodId, string routeName, IBnetHandler handler)
    {
        var route = (ServiceHash: serviceHash, MethodId: methodId);
        _hashHandlers[route] = handler;
        _hashRouteNames[route] = routeName;
    }

    private void RegisterLegacyRoute(uint serviceId, uint methodId, string routeName, IBnetHandler handler)
    {
        var route = (ServiceId: serviceId, MethodId: methodId);
        _legacyHandlers[route] = handler;
        _legacyRouteNames[route] = routeName;
    }

    private bool TryResolveRoute(
        uint serviceId,
        uint serviceHash,
        uint methodId,
        out IBnetHandler handler,
        out string routeName)
    {
        if (serviceHash != 0 &&
            _hashHandlers.TryGetValue((serviceHash, methodId), out IBnetHandler? hashHandler) &&
            hashHandler is not null)
        {
            handler = hashHandler;
            routeName = _hashRouteNames[(serviceHash, methodId)];
            return true;
        }

        // Legacy fallback is only safe when header has no service_hash at all.
        if (serviceHash == 0 &&
            _legacyHandlers.TryGetValue((serviceId, methodId), out IBnetHandler? legacyHandler) &&
            legacyHandler is not null)
        {
            handler = legacyHandler;
            routeName = _legacyRouteNames[(serviceId, methodId)];
            return true;
        }

        routeName = string.Empty;
        handler = null!;
        return false;
    }
}

public sealed class BnetConnectionHandler : IBnetHandler
{
    private readonly ILogger<BnetConnectionHandler> _logger;

    public BnetConnectionHandler(ILogger<BnetConnectionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (methodId != 1)
        {
            _logger.LogWarning(
                "[Bnet] Connection handler received unexpected route ServiceId={ServiceId} ServiceHash=0x{ServiceHash:X8} MethodId={MethodId}. ConnectionId={ConnectionId}",
                serviceId,
                serviceHash,
                methodId,
                context.ConnectionId);
            return AuthDispatchResult.Continue;
        }

        _logger.LogInformation(
            "[Bnet] Client requested connection (BGS SDK). Token: {Token}. ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
            token,
            context.ConnectionId,
            payload.Length);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        uint serverLabel = unchecked((uint)Environment.ProcessId);
        uint serverEpoch = (uint)Math.Max(1, now.ToUnixTimeSeconds());
        ulong serverTimeMilliseconds = (ulong)Math.Max(1, now.ToUnixTimeMilliseconds());

        BnetConnectPayloadParser.TryReadConnectRequestHints(payload, out ConnectRequestHints requestHints);
        ProcessId clientProcessId = requestHints.HasClientId ? requestHints.ClientProcessId : new ProcessId(2, 1);
        bool useBindlessRpc = requestHints.UseBindlessRpc;

        var responsePayload = new ArrayBufferWriter<byte>(32);
        var writer = new ProtobufWriter(responsePayload);

        WriteProcessId(ref writer, fieldNumber: 1, label: serverLabel, epoch: serverEpoch);
        WriteProcessId(ref writer, fieldNumber: 2, label: clientProcessId.Label, epoch: clientProcessId.Epoch);

        BnetBindPayloadParser.TryCountEmbeddedBindImportedServices(
            payload,
            out int embeddedImportedServices,
            out bool hasEmbeddedBindRequest);

        if (hasEmbeddedBindRequest)
        {
            BnetBindPayloadParser.LogEmbeddedBindStructure(
                payload,
                _logger,
                token,
                context.ConnectionId);

            if (embeddedImportedServices > 0)
            {
                // Build nested BindResponse:
                // bind_response.field(1) = imported_service_id (repeated)
                var bindResponsePayload = new ArrayBufferWriter<byte>(Math.Max(16, embeddedImportedServices * 3));
                var bindWriter = new ProtobufWriter(bindResponsePayload);
                for (int i = 0; i < embeddedImportedServices; i++)
                {
                    bindWriter.WriteTag(fieldNumber: 1, wireType: 0);
                    bindWriter.WriteVarint(BnetBindPayloadParser.ImportedServiceIdBase + (uint)i);
                }

                // ConnectResponse.field(4) = bind_response (length-delimited)
                writer.WriteTag(fieldNumber: 4, wireType: 2);
                writer.WriteLengthPrefixedBytes(bindResponsePayload.WrittenSpan);
            }

            _logger.LogInformation(
                "[Bnet] ConnectRequest includes embedded BindRequest. Token: {Token}. ImportedServices={ImportedServices}, ConnectionId={ConnectionId}",
                token,
                embeddedImportedServices,
                context.ConnectionId);
        }

        // Field 6: server_time (milliseconds since Unix epoch)
        writer.WriteTag(fieldNumber: 6, wireType: 0);
        writer.WriteVarint(serverTimeMilliseconds);

        // Field 7: use_bindless_rpc
        writer.WriteTag(fieldNumber: 7, wireType: 0);
        writer.WriteVarint(useBindlessRpc ? 1UL : 0UL);

        await context.SendBnetResponseAsync(token, responsePayload.WrittenMemory, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation(
            "[Bnet] ConnectResponse sent. Token: {Token}. ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}, ClientIdLabel={ClientIdLabel}, ClientIdEpoch={ClientIdEpoch}, UseBindlessRpc={UseBindlessRpc}, ServerEpoch={ServerEpoch}",
            token,
            context.ConnectionId,
            responsePayload.WrittenCount,
            clientProcessId.Label,
            clientProcessId.Epoch,
            useBindlessRpc,
            serverEpoch);

        return AuthDispatchResult.Continue;
    }

    private static void WriteProcessId(ref ProtobufWriter writer, int fieldNumber, uint label, uint epoch)
    {
        // ProcessId = message { uint32 label = 1; uint32 epoch = 2; }
        int nestedSize =
            1 + ProtobufWriter.GetVarintLength(label) +
            1 + ProtobufWriter.GetVarintLength(epoch);

        writer.WriteTag(fieldNumber, wireType: 2);
        writer.WriteVarint((ulong)nestedSize);
        writer.WriteTag(fieldNumber: 1, wireType: 0);
        writer.WriteVarint(label);
        writer.WriteTag(fieldNumber: 2, wireType: 0);
        writer.WriteVarint(epoch);
    }
}

public sealed class BnetBindHandler : IBnetHandler
{
    private readonly ILogger<BnetBindHandler> _logger;

    public BnetBindHandler(ILogger<BnetBindHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (methodId != 2)
        {
            _logger.LogWarning(
                "[Bnet] Bind handler received unexpected route ServiceId={ServiceId} ServiceHash=0x{ServiceHash:X8} MethodId={MethodId}. ConnectionId={ConnectionId}",
                serviceId,
                serviceHash,
                methodId,
                context.ConnectionId);
            return AuthDispatchResult.Continue;
        }

        BnetBindPayloadParser.TryCountImportedServices(payload, out int importedServiceCount);

        var responsePayload = new ArrayBufferWriter<byte>(Math.Max(8, importedServiceCount * 3));
        var writer = new ProtobufWriter(responsePayload);

        for (int i = 0; i < importedServiceCount; i++)
        {
            writer.WriteTag(fieldNumber: 1, wireType: 0); // imported_service_id
            writer.WriteVarint(BnetBindPayloadParser.ImportedServiceIdBase + (uint)i);
        }

        await context.SendBnetResponseAsync(token, responsePayload.WrittenMemory, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation(
            "[Bnet] BindResponse sent. Token: {Token}. ConnectionId={ConnectionId}, ImportedServices={ImportedServices}",
            token,
            context.ConnectionId,
            importedServiceCount);

        return AuthDispatchResult.Continue;
    }
}

public sealed class BnetKeepAliveHandler : IBnetHandler
{
    private readonly ILogger<BnetKeepAliveHandler> _logger;

    public BnetKeepAliveHandler(ILogger<BnetKeepAliveHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (methodId != 5)
        {
            _logger.LogWarning(
                "[Bnet] KeepAlive handler received unexpected route ServiceId={ServiceId} ServiceHash=0x{ServiceHash:X8} MethodId={MethodId}. ConnectionId={ConnectionId}",
                serviceId,
                serviceHash,
                methodId,
                context.ConnectionId);
            return AuthDispatchResult.Continue;
        }

        _logger.LogInformation(
            "[Bnet] KeepAlive received. Token: {Token}. ConnectionId={ConnectionId}",
            token,
            context.ConnectionId);

        await context.SendBnetResponseAsync(token, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
        return AuthDispatchResult.Continue;
    }
}

public sealed class BnetConnectionControlHandler : IBnetHandler
{
    private readonly ILogger<BnetConnectionControlHandler> _logger;

    public BnetConnectionControlHandler(ILogger<BnetConnectionControlHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (methodId == 6)
        {
            // ConnectionService.Encrypt -> reply with NoData success.
            _logger.LogInformation(
                "[Bnet] Encrypt request received. Token={Token}. ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                payload.Length);

            await context.SendBnetResponseAsync(token, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
            return AuthDispatchResult.Continue;
        }

        if (methodId == 7)
        {
            // ConnectionService.RequestDisconnect -> close auth socket gracefully.
            _logger.LogInformation(
                "[Bnet] Disconnect request received. Token={Token}. ConnectionId={ConnectionId}. Closing connection.",
                token,
                context.ConnectionId);

            return AuthDispatchResult.Disconnect;
        }

        _logger.LogWarning(
            "[Bnet] Connection control handler received unexpected method. ServiceId={ServiceId}, ServiceHash=0x{ServiceHash:X8}, MethodId={MethodId}, ConnectionId={ConnectionId}",
            serviceId,
            serviceHash,
            methodId,
            context.ConnectionId);

        return AuthDispatchResult.Continue;
    }
}

internal static class BnetClientVariantResolver
{
    public static readonly uint PlatformTypeWin = ToFourCc("Win");
    public static readonly uint PlatformTypeMac = ToFourCc("Mac");
    public static readonly uint ArchX86 = ToFourCc("x86");
    public static readonly uint ArchX64 = ToFourCc("x64");
    public static readonly uint ArchArm64 = ToFourCc("A64");
    public static readonly uint TypeRetail = ToFourCc("WoW");
    public static readonly uint TypeRetailChina = ToFourCc("WoWC");
    public static readonly uint TypeBeta = ToFourCc("WoWB");
    public static readonly uint TypeBetaRelease = ToFourCc("WoWE");
    public static readonly uint TypePtr = ToFourCc("WoWT");
    public static readonly uint TypePtrRelease = ToFourCc("WoWR");

    public static uint ResolvePlatformType(string platformToken)
    {
        if (!string.IsNullOrWhiteSpace(platformToken) &&
            platformToken.StartsWith("Mac", StringComparison.OrdinalIgnoreCase))
        {
            return PlatformTypeMac;
        }

        return PlatformTypeWin;
    }

    public static uint ResolveArch(string platformToken)
    {
        if (string.IsNullOrWhiteSpace(platformToken))
        {
            return ArchX64;
        }

        string token = platformToken.Trim();
        if (token.Equals("WinA", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("MacA", StringComparison.OrdinalIgnoreCase) ||
            token.Equals("A64", StringComparison.OrdinalIgnoreCase))
        {
            return ArchArm64;
        }

        if (token.Contains("64", StringComparison.OrdinalIgnoreCase))
        {
            return ArchX64;
        }

        if (token.Contains("86", StringComparison.OrdinalIgnoreCase) ||
            token.EndsWith("32", StringComparison.OrdinalIgnoreCase))
        {
            return ArchX86;
        }

        return ArchX64;
    }

    public static uint ResolveType(string programToken)
    {
        if (string.IsNullOrWhiteSpace(programToken))
        {
            return TypeRetail;
        }

        string token = programToken.Trim();

        if (token.Equals("WoWC", StringComparison.OrdinalIgnoreCase))
        {
            return TypeRetailChina;
        }

        if (token.Equals("WoWB", StringComparison.OrdinalIgnoreCase))
        {
            return TypeBeta;
        }

        if (token.Equals("WoWE", StringComparison.OrdinalIgnoreCase))
        {
            return TypeBetaRelease;
        }

        if (token.Equals("WoWT", StringComparison.OrdinalIgnoreCase))
        {
            return TypePtr;
        }

        if (token.Equals("WoWR", StringComparison.OrdinalIgnoreCase))
        {
            return TypePtrRelease;
        }

        return TypeRetail;
    }

    private static uint ToFourCc(string text)
    {
        uint value = 0;
        for (int i = 0; i < text.Length && i < 4; i++)
        {
            value <<= 8;
            value |= text[i];
        }

        return value;
    }
}

public sealed class BnetAuthenticationLogonHandler : IBnetHandler
{
    private const string ExpectedLogin = "AIMAYA";
    private const string ExpectedPassword = "AIMAYA";

    // TrinityCore session bootstrap constants (Battlenet::Session::HandleVerifyWebCredentials).
    private const ulong AccountEntityHigh = 0x0100000000000000UL;
    private const ulong GameAccountEntityHigh = 0x0200000200576F57UL;

    private static readonly byte[] GeoCountryUsBytes = "US"u8.ToArray();

    private readonly ILogger<BnetAuthenticationLogonHandler> _logger;
    private readonly IDatabaseService _databaseService;

    public BnetAuthenticationLogonHandler(
        ILogger<BnetAuthenticationLogonHandler> logger,
        IDatabaseService databaseService)
    {
        _logger = logger;
        _databaseService = databaseService;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (methodId != 1)
        {
            _logger.LogWarning(
                "[Bnet][Auth] Logon handler received unexpected route ServiceId={ServiceId} ServiceHash=0x{ServiceHash:X8} MethodId={MethodId}. ConnectionId={ConnectionId}",
                serviceId,
                serviceHash,
                methodId,
                context.ConnectionId);
            return AuthDispatchResult.Continue;
        }

        BnetAuthenticationPayloadParser.TryReadLogonRequest(payload, out BnetLogonRequestInfo requestInfo);
        _logger.LogInformation(
            "[Bnet][Auth] Logon request received. Token={Token}, ConnectionId={ConnectionId}, Program={Program}, Platform={Platform}, Locale={Locale}, Build={Build}, Email={Email}, CachedWebCreds={CachedCredsBytes}",
            token,
            context.ConnectionId,
            requestInfo.Program,
            requestInfo.Platform,
            requestInfo.Locale,
            requestInfo.ApplicationVersion,
            requestInfo.Email,
            requestInfo.CachedWebCredentialsLength);

        string normalizedLogin = NormalizeLogin(requestInfo.Email);
        if (string.IsNullOrEmpty(normalizedLogin))
        {
            // Retail standalone auth path (without launcher) may not provide clear login in Logon payload.
            // Keep adapter test flow deterministic by pinning to AIMAYA in this case.
            normalizedLogin = ExpectedLogin;
            _logger.LogInformation(
                "[Bnet][Auth] Logon payload has no explicit login. Using adapter test account {Login}. ConnectionId={ConnectionId}",
                ExpectedLogin.ToLowerInvariant(),
                context.ConnectionId);
        }

        string normalizedPassword = NormalizePassword(requestInfo.Password, normalizedLogin);

        if (!normalizedLogin.Equals(ExpectedLogin, StringComparison.Ordinal) ||
            !normalizedPassword.Equals(ExpectedPassword, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "[Bnet][Auth] Credentials rejected. ConnectionId={ConnectionId}, Login={Login}",
                context.ConnectionId,
                string.IsNullOrEmpty(normalizedLogin) ? "<empty>" : normalizedLogin);

            // Invalid credentials in adapter-mode auth gate.
            await context.SendBnetStatusAsync(token, status: 1u, cancellationToken).ConfigureAwait(false);
            return AuthDispatchResult.Disconnect;
        }

        _logger.LogInformation("[Bnet][Auth] Credentials accepted. Welcome, aimaya!");

        AccountData? account;
        try
        {
            account = await _databaseService.GetAccountData(normalizedLogin, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "[Bnet][Auth] Account lookup failed for '{Lookup}'. ConnectionId={ConnectionId}",
                normalizedLogin,
                context.ConnectionId);
            await context.SendBnetStatusAsync(token, status: 1u, cancellationToken).ConfigureAwait(false);
            return AuthDispatchResult.Disconnect;
        }

        if (account is null)
        {
            _logger.LogWarning(
                "[Bnet][Auth] Credentials rejected. Account '{Lookup}' does not exist in acore_auth.account. ConnectionId={ConnectionId}",
                normalizedLogin,
                context.ConnectionId);
            await context.SendBnetStatusAsync(token, status: 1u, cancellationToken).ConfigureAwait(false);
            return AuthDispatchResult.Disconnect;
        }

        int accountId = account.Id;
        string accountUsername = string.IsNullOrWhiteSpace(account.Username)
            ? ExpectedLogin
            : account.Username.Trim().ToUpperInvariant();

        uint clientPlatformType = BnetClientVariantResolver.ResolvePlatformType(requestInfo.Platform);
        uint clientArch = BnetClientVariantResolver.ResolveArch(requestInfo.Platform);
        uint clientType = BnetClientVariantResolver.ResolveType(requestInfo.Program);

        context.SetValue(BnetContextKeys.AccountId, accountId);
        context.SetValue(BnetContextKeys.GameAccountName, accountUsername);
        context.SetValue(BnetContextKeys.ClientPlatformFourCc, clientPlatformType);
        context.SetValue(BnetContextKeys.ClientArchFourCc, clientArch);
        context.SetValue(BnetContextKeys.ClientTypeFourCc, clientType);

        byte[] sessionKey64 = new byte[64];
        RandomNumberGenerator.Fill(sessionKey64);

        // AzerothCore auth schema expects 40-byte session_key.
        byte[] sessionKey40 = new byte[40];
        Buffer.BlockCopy(sessionKey64, 0, sessionKey40, 0, sessionKey40.Length);

        try
        {
            bool updated = await _databaseService.UpdateSessionKey(accountId, sessionKey40, sessionKey64, cancellationToken).ConfigureAwait(false);
            if (!updated)
            {
                _logger.LogWarning(
                    "[Bnet][Auth] Session key update affected 0 rows. AccountId={AccountId}, ConnectionId={ConnectionId}",
                    accountId,
                    context.ConnectionId);
                await context.SendBnetStatusAsync(token, status: 1u, cancellationToken).ConfigureAwait(false);
                return AuthDispatchResult.Disconnect;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "[Bnet][Auth] Failed to persist session key for AccountId={AccountId}. ConnectionId={ConnectionId}",
                accountId,
                context.ConnectionId);
            await context.SendBnetStatusAsync(token, status: 1u, cancellationToken).ConfigureAwait(false);
            return AuthDispatchResult.Disconnect;
        }

        // RPC response for AuthenticationService.Logon has NoData payload on success.
        await context.SendBnetResponseAsync(token, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);

        var logonResultPayload = new ArrayBufferWriter<byte>(256);
        var writer = new ProtobufWriter(logonResultPayload);

        // LogonResult.error_code = 0 (success)
        writer.WriteTag(fieldNumber: 1, wireType: 0);
        writer.WriteVarint(0);

        // LogonResult.account_id
        WriteEntityId(ref writer, fieldNumber: 2, high: AccountEntityHigh, low: (ulong)accountId);

        // LogonResult.game_account_id (single entry is enough for bootstrap)
        WriteEntityId(ref writer, fieldNumber: 3, high: GameAccountEntityHigh, low: (ulong)accountId);

        // GeoIP and session key mirror Trinity happy-path shape.
        writer.WriteTag(fieldNumber: 8, wireType: 2);
        writer.WriteLengthPrefixedBytes(GeoCountryUsBytes);
        writer.WriteTag(fieldNumber: 9, wireType: 2);
        writer.WriteLengthPrefixedBytes(sessionKey64);

        await context
            .SendBnetRequestAsync(
                BnetServiceHashes.AuthenticationListenerOriginal,
                methodId: 5, // AuthenticationListener.OnLogonComplete
                logonResultPayload.WrittenMemory,
                cancellationToken)
            .ConfigureAwait(false);

        string sessionKeySha256 = Convert.ToHexString(SHA256.HashData(sessionKey64));
        _logger.LogInformation(
            "[Bnet][Auth] OnLogonComplete sent. ConnectionId={ConnectionId}, AccountId={AccountId}, Username={Username}, SessionKeyBytes={SessionKeyBytes}, SessionKeySha256={SessionKeySha256}",
            context.ConnectionId,
            accountId,
            accountUsername,
            sessionKey64.Length,
            sessionKeySha256);

        return AuthDispatchResult.Continue;
    }

    private static string NormalizeLogin(string rawLogin)
    {
        if (string.IsNullOrWhiteSpace(rawLogin))
        {
            return string.Empty;
        }

        string login = rawLogin.Trim();
        int atIndex = login.IndexOf('@');
        if (atIndex > 0)
        {
            login = login[..atIndex];
        }

        return login.ToUpperInvariant();
    }

    private static string NormalizePassword(string rawPassword, string normalizedLogin)
    {
        if (!string.IsNullOrWhiteSpace(rawPassword))
        {
            return rawPassword.Trim().ToUpperInvariant();
        }

        // Retail standalone logon payload often does not carry clear-text password.
        // In test mode, treat missing password as "same as login".
        return normalizedLogin;
    }

    private static void WriteEntityId(ref ProtobufWriter writer, int fieldNumber, ulong high, ulong low)
    {
        // EntityId = message { fixed64 high = 1; fixed64 low = 2; }
        const int nestedPayloadSize = 1 + sizeof(ulong) + 1 + sizeof(ulong);

        writer.WriteTag(fieldNumber: fieldNumber, wireType: 2);
        writer.WriteVarint((ulong)nestedPayloadSize);

        writer.WriteTag(fieldNumber: 1, wireType: 1); // fixed64 high
        writer.WriteFixed64(high);

        writer.WriteTag(fieldNumber: 2, wireType: 1); // fixed64 low
        writer.WriteFixed64(low);
    }
}

public sealed class BnetAccountHandler : IBnetHandler
{
    private readonly ILogger<BnetAccountHandler> _logger;

    public BnetAccountHandler(ILogger<BnetAccountHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "[Bnet][Account] Received MethodId={MethodId}. Token={Token}. ConnectionId={ConnectionId}, ServiceHash=0x{ServiceHash:X8}, PayloadBytes={PayloadBytes}",
            methodId,
            token,
            context.ConnectionId,
            serviceHash,
            payload.Length);

        await context.SendBnetResponseAsync(token, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
        return AuthDispatchResult.Continue;
    }
}

public sealed class BnetGameUtilitiesHandler : IBnetHandler
{
    private readonly ILogger<BnetGameUtilitiesHandler> _logger;
    private readonly IDatabaseService _databaseService;

    public BnetGameUtilitiesHandler(
        ILogger<BnetGameUtilitiesHandler> logger,
        IDatabaseService databaseService)
    {
        _logger = logger;
        _databaseService = databaseService;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint serviceHash,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (methodId == 1)
        {
            BnetGameUtilitiesPayloadParser.TryReadClientRequestInfo(payload, out BnetGameUtilitiesRequestInfo requestInfo);

            _logger.LogInformation(
                "[Bnet][GameUtilities] ProcessClientRequest received. Token={Token}, ConnectionId={ConnectionId}, Command={Command}, Attributes={Attributes}, SubRegion={SubRegion}, RealmAddress={RealmAddress}, HasAccountId={HasAccountId}, HasGameAccountId={HasGameAccountId}, HasClientInfo={HasClientInfo}, ClientSecretBytes={ClientSecretBytes}, ClientInfoRawBytes={ClientInfoRawBytes}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                requestInfo.Command,
                requestInfo.AttributeCount,
                requestInfo.RealmListSubRegion,
                requestInfo.RealmAddress,
                requestInfo.HasAccountId,
                requestInfo.HasGameAccountId,
                requestInfo.HasClientInfo,
                requestInfo.ClientSecret32?.Length ?? 0,
                requestInfo.ClientInfoRawBytes,
                payload.Length);

            if (requestInfo.ClientSecret32 is { Length: 32 })
            {
                context.SetValue(BnetContextKeys.ClientSecret32, requestInfo.ClientSecret32);
            }
            else if (requestInfo.HasClientInfo)
            {
                _logger.LogWarning(
                    "[Bnet][GameUtilities] Param_ClientInfo present but client secret was not extracted. Token={Token}, ConnectionId={ConnectionId}, Command={Command}, RawBytes={RawBytes}, RawHeadHex={RawHeadHex}, Details={Details}",
                    token,
                    context.ConnectionId,
                    requestInfo.Command,
                    requestInfo.ClientInfoRawBytes,
                    requestInfo.ClientInfoRawHeadHex ?? "<none>",
                    requestInfo.ClientInfoExtractDetails ?? "<none>");
            }

            ReadOnlyMemory<byte> responsePayload = BnetGameUtilitiesPayloadFactory.GetClientResponsePayload(requestInfo.Command);

            if (requestInfo.Command == GameUtilitiesCommandKind.RealmListRequest)
            {
                IReadOnlyList<RealmData> realms;
                try
                {
                    realms = await _databaseService.GetWorldList(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(
                        ex,
                        "[Bnet][GameUtilities] Failed to load realms from DB. Falling back to synthetic realm list. ConnectionId={ConnectionId}",
                        context.ConnectionId);
                    realms = Array.Empty<RealmData>();
                }

                if (realms.Count == 0)
                {
                    realms = BnetGameUtilitiesPayloadFactory.FallbackRealmList;
                }

                if (RealmListPacketBuilder.TryBuildBnetRealmListBlobs(
                        realms,
                        requestInfo.RealmListSubRegion,
                        out byte[] realmListBlob,
                        out byte[] characterCountBlob,
                        clientBuild: 66102))
                {
                    responsePayload = BnetGameUtilitiesPayloadFactory.BuildRealmListResponsePayload(realmListBlob, characterCountBlob);
                }
                else
                {
                    _logger.LogWarning(
                        "[Bnet][GameUtilities] Failed to build realm list payload. ConnectionId={ConnectionId}, RealmCount={RealmCount}",
                        context.ConnectionId,
                        realms.Count);
                    responsePayload = ReadOnlyMemory<byte>.Empty;
                }
            }

            if (requestInfo.Command is GameUtilitiesCommandKind.RealmJoinRequest or GameUtilitiesCommandKind.RealmJoinTicketRequest)
            {
                IReadOnlyList<RealmData> realms;
                try
                {
                    realms = await _databaseService.GetWorldList(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(
                        ex,
                        "[Bnet][GameUtilities] Failed to load realms for join from DB. Falling back to synthetic realm list. ConnectionId={ConnectionId}",
                        context.ConnectionId);
                    realms = Array.Empty<RealmData>();
                }

                if (realms.Count == 0)
                {
                    realms = BnetGameUtilitiesPayloadFactory.FallbackRealmList;
                }

                RealmData selectedRealm = BnetGameUtilitiesPayloadFactory.SelectRealmForJoin(realms, requestInfo.RealmAddress);
                if (RealmListPacketBuilder.TryBuildBnetServerAddressesBlob(selectedRealm, out byte[] serverAddressesBlob))
                {
                    int accountId = context.TryGetValue(BnetContextKeys.AccountId, out int storedAccountId)
                        ? storedAccountId
                        : 0;

                    if (accountId <= 0)
                    {
                        _logger.LogWarning(
                            "[Bnet][GameUtilities] Missing authenticated account id in context while building RealmJoin payload. ConnectionId={ConnectionId}",
                            context.ConnectionId);
                    }

                    string gameAccountName = context.TryGetValue(BnetContextKeys.GameAccountName, out string storedGameAccountName)
                        && !string.IsNullOrWhiteSpace(storedGameAccountName)
                            ? storedGameAccountName
                            : "AIMAYA";

                    uint platformType = context.TryGetValue(BnetContextKeys.ClientPlatformFourCc, out uint storedPlatformType)
                        ? storedPlatformType
                        : BnetClientVariantResolver.PlatformTypeWin;

                    uint clientArch = context.TryGetValue(BnetContextKeys.ClientArchFourCc, out uint storedClientArch)
                        ? storedClientArch
                        : BnetClientVariantResolver.ArchX64;

                    uint clientType = context.TryGetValue(BnetContextKeys.ClientTypeFourCc, out uint storedClientType)
                        ? storedClientType
                        : BnetClientVariantResolver.TypeRetail;

                    byte[] joinSecret = RandomNumberGenerator.GetBytes(32);
                    responsePayload = BnetGameUtilitiesPayloadFactory.BuildRealmJoinResponsePayload(
                        serverAddressesBlob,
                        accountId,
                        gameAccountName,
                        platformType,
                        clientType,
                        clientArch,
                        joinSecret);

                    byte[]? clientSecret32 = requestInfo.ClientSecret32 is { Length: 32 }
                        ? requestInfo.ClientSecret32
                        : (context.TryGetValue(BnetContextKeys.ClientSecret32, out byte[] storedClientSecret) && storedClientSecret.Length == 32
                            ? storedClientSecret
                            : null);

                    if (accountId > 0 && clientSecret32 is { Length: 32 })
                    {
                        byte[] keyData64 = new byte[64];
                        Buffer.BlockCopy(clientSecret32, 0, keyData64, 0, 32);
                        Buffer.BlockCopy(joinSecret, 0, keyData64, 32, 32);

                        try
                        {
                            bool keyUpdated = await _databaseService
                                .UpsertWorldSessionMaterial(accountId, keyData64, cancellationToken)
                                .ConfigureAwait(false);

                            _logger.LogInformation(
                            "[Bnet][GameUtilities] RealmJoin key_data {Status}. Token={Token}, ConnectionId={ConnectionId}, AccountId={AccountId}, KeyDataSha256={KeyDataSha256}",
                            keyUpdated ? "upserted" : "not-upserted",
                            token,
                            context.ConnectionId,
                            accountId,
                            Convert.ToHexString(SHA256.HashData(keyData64)));
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(
                                ex,
                                "[Bnet][GameUtilities] Failed to upsert RealmJoin key_data. Token={Token}, ConnectionId={ConnectionId}, AccountId={AccountId}",
                                token,
                                context.ConnectionId,
                                accountId);
                        }
                    }
                    else
                    {
                        _logger.LogWarning(
                            "[Bnet][GameUtilities] RealmJoin key_data not updated (missing inputs). Token={Token}, ConnectionId={ConnectionId}, AccountId={AccountId}, ClientSecretBytes={ClientSecretBytes}",
                            token,
                            context.ConnectionId,
                            accountId,
                            clientSecret32?.Length ?? 0);
                    }
                }
                else
                {
                    _logger.LogWarning(
                        "[Bnet][GameUtilities] Failed to build server addresses blob for join. ConnectionId={ConnectionId}, RealmAddress={RealmAddress}",
                        context.ConnectionId,
                        requestInfo.RealmAddress);
                    responsePayload = ReadOnlyMemory<byte>.Empty;
                }
            }

            await context.SendBnetResponseAsync(token, responsePayload, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "[Bnet][GameUtilities] ProcessClientRequest response sent. Token={Token}, ConnectionId={ConnectionId}, Command={Command}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                requestInfo.Command,
                responsePayload.Length);

            return AuthDispatchResult.Continue;
        }

        if (methodId == 10)
        {
            BnetGameUtilitiesPayloadParser.TryReadGetAllValuesForAttributeRequest(payload, out BnetGetAllValuesRequestInfo requestInfo);

            _logger.LogInformation(
                "[Bnet][GameUtilities] GetAllValuesForAttribute received. Token={Token}, ConnectionId={ConnectionId}, AttributeKey={AttributeKey}, Program={Program}, HasAgentId={HasAgentId}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                requestInfo.AttributeKey,
                requestInfo.Program,
                requestInfo.HasAgentId,
                payload.Length);

            ReadOnlyMemory<byte> responsePayload = BnetGameUtilitiesPayloadFactory.GetAllValuesForAttributeResponsePayload(requestInfo.AttributeKey);
            await context.SendBnetResponseAsync(token, responsePayload, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "[Bnet][GameUtilities] GetAllValuesForAttribute response sent. Token={Token}, ConnectionId={ConnectionId}, Values={ValuesCount}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                responsePayload.IsEmpty ? 0 : 1,
                responsePayload.Length);

            return AuthDispatchResult.Continue;
        }

        if (methodId == 11)
        {
            _logger.LogInformation(
                "[Bnet][GameUtilities] RegisterUtilities received. Token={Token}, ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                payload.Length);

            ReadOnlyMemory<byte> responsePayload = BnetGameUtilitiesPayloadFactory.RegisterUtilitiesResponsePayload;
            await context.SendBnetResponseAsync(token, responsePayload, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "[Bnet][GameUtilities] RegisterUtilities response sent. Token={Token}, ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                responsePayload.Length);

            return AuthDispatchResult.Continue;
        }

        if (methodId == 12)
        {
            _logger.LogInformation(
                "[Bnet][GameUtilities] UnregisterUtilities received. Token={Token}, ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
                token,
                context.ConnectionId,
                payload.Length);

            await context.SendBnetResponseAsync(token, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
            return AuthDispatchResult.Continue;
        }

        _logger.LogWarning(
            "[Bnet][GameUtilities] Handler received unexpected method. ServiceId={ServiceId}, ServiceHash=0x{ServiceHash:X8}, MethodId={MethodId}, ConnectionId={ConnectionId}",
            serviceId,
            serviceHash,
            methodId,
            context.ConnectionId);
        return AuthDispatchResult.Continue;
    }
}

internal readonly record struct BnetGetAllValuesRequestInfo(
    string AttributeKey,
    uint Program,
    bool HasAgentId);

internal readonly record struct BnetLogonRequestInfo(
    string Program,
    string Platform,
    string Locale,
    string Email,
    string Password,
    int ApplicationVersion,
    int CachedWebCredentialsLength,
    string DeviceId);

internal static class BnetAuthenticationPayloadParser
{
    private const int MaxPayloadBytes = 512 * 1024;

    public static bool TryReadLogonRequest(ReadOnlySequence<byte> payload, out BnetLogonRequestInfo info)
    {
        string program = string.Empty;
        string platform = string.Empty;
        string locale = string.Empty;
        string email = string.Empty;
        string password = string.Empty;
        int applicationVersion = 0;
        int cachedWebCredentialsLength = 0;
        string deviceId = string.Empty;

        if (!TryGetPayloadSpan(payload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            info = default;
            return false;
        }

        try
        {
            var reader = new ProtobufVarintReader(span);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    info = new BnetLogonRequestInfo(program, platform, locale, email, password, applicationVersion, cachedWebCredentialsLength, deviceId);
                    return false;
                }

                switch (wireType)
                {
                    case ProtobufWireType.Varint:
                        if (!reader.TryReadVarint(out ulong rawVarint))
                        {
                            info = new BnetLogonRequestInfo(program, platform, locale, email, password, applicationVersion, cachedWebCredentialsLength, deviceId);
                            return false;
                        }

                        if (fieldNumber == 6 && rawVarint <= int.MaxValue)
                        {
                            applicationVersion = (int)rawVarint;
                        }
                        break;
                    case ProtobufWireType.LengthDelimited:
                        if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> bytes))
                        {
                            info = new BnetLogonRequestInfo(program, platform, locale, email, password, applicationVersion, cachedWebCredentialsLength, deviceId);
                            return false;
                        }

                        switch (fieldNumber)
                        {
                            case 1:
                                program = Encoding.UTF8.GetString(bytes);
                                break;
                            case 2:
                                platform = Encoding.UTF8.GetString(bytes);
                                break;
                            case 3:
                                locale = Encoding.UTF8.GetString(bytes);
                                break;
                            case 4:
                                email = Encoding.UTF8.GetString(bytes);
                                break;
                            case 5:
                                // Best-effort extraction for standalone credential testing.
                                password = Encoding.UTF8.GetString(bytes);
                                break;
                            case 12:
                                cachedWebCredentialsLength = bytes.Length;
                                break;
                            case 15:
                                deviceId = Encoding.UTF8.GetString(bytes);
                                break;
                        }
                        break;
                    default:
                        if (!reader.TrySkipField(wireType))
                        {
                            info = new BnetLogonRequestInfo(program, platform, locale, email, password, applicationVersion, cachedWebCredentialsLength, deviceId);
                            return false;
                        }
                        break;
                }
            }

            info = new BnetLogonRequestInfo(program, platform, locale, email, password, applicationVersion, cachedWebCredentialsLength, deviceId);
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private static bool TryGetPayloadSpan(
        ReadOnlySequence<byte> payload,
        out byte[]? rented,
        out ReadOnlySpan<byte> span)
    {
        rented = null;
        span = default;

        if (payload.Length < 0 || payload.Length > MaxPayloadBytes)
        {
            return false;
        }

        if (payload.IsSingleSegment)
        {
            span = payload.FirstSpan;
            return true;
        }

        int length = (int)payload.Length;
        rented = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> destination = rented.AsSpan(0, length);
        payload.CopyTo(destination);
        span = destination;
        return true;
    }
}

internal static class BnetBindPayloadParser
{
    private const int MaxPayloadBytes = 256 * 1024;
    public const uint ImportedServiceIdBase = 100;

    public static void LogEmbeddedBindStructure(
        ReadOnlySequence<byte> connectPayload,
        ILogger logger,
        uint token,
        uint connectionId)
    {
        if (!TryGetPayloadSpan(connectPayload, out byte[]? rented, out ReadOnlySpan<byte> connectSpan))
        {
            logger.LogInformation(
                "[BIND DEBUG] Unable to map ConnectRequest payload to span. Token={Token}, ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
                token,
                connectionId,
                connectPayload.Length);
            return;
        }

        try
        {
            var reader = new ProtobufVarintReader(connectSpan);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    logger.LogInformation(
                        "[BIND DEBUG] Failed to read ConnectRequest field header. Token={Token}, ConnectionId={ConnectionId}",
                        token,
                        connectionId);
                    break;
                }

                if (fieldNumber == 2 && wireType == ProtobufWireType.LengthDelimited)
                {
                    if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> bindPayload))
                    {
                        logger.LogInformation(
                            "[BIND DEBUG] Failed to read embedded BindRequest payload. Token={Token}, ConnectionId={ConnectionId}",
                            token,
                            connectionId);
                        break;
                    }

                    logger.LogInformation(
                        "[BIND DEBUG] Embedded BindRequest Length: {Length}. Token={Token}, ConnectionId={ConnectionId}",
                        bindPayload.Length,
                        token,
                        connectionId);

                    var nested = new ProtobufVarintReader(bindPayload);
                    while (!nested.End)
                    {
                        if (!nested.TryReadFieldHeader(out uint nestedField, out ProtobufWireType nestedWire))
                        {
                            logger.LogInformation(
                                "[BIND DEBUG] Failed to read nested BindRequest field header. Token={Token}, ConnectionId={ConnectionId}",
                                token,
                                connectionId);
                            break;
                        }

                        logger.LogInformation(
                            "[BIND DEBUG] Found nested tag: Field={Field}, WireType={WireType}. Token={Token}, ConnectionId={ConnectionId}",
                            nestedField,
                            (byte)nestedWire,
                            token,
                            connectionId);

                        if (!nested.TrySkipField(nestedWire))
                        {
                            logger.LogInformation(
                                "[BIND DEBUG] Failed to skip nested field payload. Field={Field}, WireType={WireType}, Token={Token}, ConnectionId={ConnectionId}",
                                nestedField,
                                (byte)nestedWire,
                                token,
                                connectionId);
                            break;
                        }
                    }

                    // Typically only one bind_request in ConnectRequest.
                    continue;
                }

                if (!reader.TrySkipField(wireType))
                {
                    logger.LogInformation(
                        "[BIND DEBUG] Failed to skip ConnectRequest field payload. Field={Field}, WireType={WireType}, Token={Token}, ConnectionId={ConnectionId}",
                        fieldNumber,
                        (byte)wireType,
                        token,
                        connectionId);
                    break;
                }
            }
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public static bool TryCountImportedServices(ReadOnlySequence<byte> bindPayload, out int importedServiceCount)
    {
        importedServiceCount = 0;
        if (!TryGetPayloadSpan(bindPayload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            return false;
        }

        try
        {
            return TryCountImportedServices(span, out importedServiceCount);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public static bool TryCountEmbeddedBindImportedServices(
        ReadOnlySequence<byte> connectPayload,
        out int importedServiceCount,
        out bool hasEmbeddedBindRequest)
    {
        importedServiceCount = 0;
        hasEmbeddedBindRequest = false;

        if (!TryGetPayloadSpan(connectPayload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            return false;
        }

        try
        {
            var reader = new ProtobufVarintReader(span);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    // Be tolerant: keep best-effort count and allow flow to continue.
                    break;
                }

                if (wireType == ProtobufWireType.LengthDelimited)
                {
                    if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> nestedPayload))
                    {
                        break;
                    }

                    // Canonical v10+ uses ConnectRequest.bind_request = field 2.
                    if (fieldNumber == 2)
                    {
                        hasEmbeddedBindRequest = true;
                        if (TryCountImportedServices(nestedPayload, out int nestedImportedServices))
                        {
                            importedServiceCount += nestedImportedServices;
                        }
                    }

                    continue;
                }

                if (!reader.TrySkipField(wireType))
                {
                    break;
                }
            }

            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private static bool TryCountImportedServices(ReadOnlySpan<byte> bindPayload, out int importedServiceCount)
    {
        importedServiceCount = 0;

        var reader = new ProtobufVarintReader(bindPayload);
        while (!reader.End)
        {
            if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
            {
                break;
            }

            if (wireType == ProtobufWireType.LengthDelimited)
            {
                if (fieldNumber == 4)
                {
                    // BindRequest.imported_service (repeated message BoundService)
                    importedServiceCount++;
                    if (!reader.TrySkipLengthDelimited())
                    {
                        break;
                    }
                    continue;
                }

                if (!reader.TrySkipLengthDelimited())
                {
                    break;
                }

                continue;
            }

            if (!reader.TrySkipField(wireType))
            {
                break;
            }
        }

        return true;
    }

    private static bool TryGetPayloadSpan(
        ReadOnlySequence<byte> payload,
        out byte[]? rented,
        out ReadOnlySpan<byte> span)
    {
        rented = null;
        span = default;

        if (payload.Length < 0 || payload.Length > MaxPayloadBytes)
        {
            return false;
        }

        if (payload.IsSingleSegment)
        {
            span = payload.FirstSpan;
            return true;
        }

        int length = (int)payload.Length;
        rented = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> destination = rented.AsSpan(0, length);
        payload.CopyTo(destination);
        span = destination;
        return true;
    }
}

internal readonly record struct ProcessId(uint Label, uint Epoch);
internal readonly record struct ConnectRequestHints(bool HasClientId, ProcessId ClientProcessId, bool UseBindlessRpc);

internal static class BnetConnectPayloadParser
{
    private const int MaxPayloadBytes = 256 * 1024;

    public static bool TryReadConnectRequestHints(ReadOnlySequence<byte> connectPayload, out ConnectRequestHints hints)
    {
        bool hasClientId = false;
        ProcessId clientProcessId = default;
        bool useBindlessRpc = true;

        if (!TryGetPayloadSpan(connectPayload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            hints = new ConnectRequestHints(false, default, true);
            return false;
        }

        try
        {
            var reader = new ProtobufVarintReader(span);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    hints = new ConnectRequestHints(hasClientId, clientProcessId, useBindlessRpc);
                    return false;
                }

                if (fieldNumber == 1 && wireType == ProtobufWireType.LengthDelimited)
                {
                    if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> processIdPayload))
                    {
                        hints = new ConnectRequestHints(hasClientId, clientProcessId, useBindlessRpc);
                        return false;
                    }

                    if (TryParseProcessId(processIdPayload, out ProcessId parsed))
                    {
                        hasClientId = true;
                        clientProcessId = parsed;
                    }

                    continue;
                }

                if (fieldNumber == 3 && wireType == ProtobufWireType.Varint)
                {
                    if (!reader.TryReadVarint(out ulong rawValue))
                    {
                        hints = new ConnectRequestHints(hasClientId, clientProcessId, useBindlessRpc);
                        return false;
                    }

                    useBindlessRpc = rawValue != 0;
                    continue;
                }

                if (!reader.TrySkipField(wireType))
                {
                    hints = new ConnectRequestHints(hasClientId, clientProcessId, useBindlessRpc);
                    return false;
                }
            }

            hints = new ConnectRequestHints(hasClientId, clientProcessId, useBindlessRpc);
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private static bool TryParseProcessId(ReadOnlySpan<byte> payload, out ProcessId processId)
    {
        processId = default;
        uint label = 0;
        uint epoch = 1;
        bool hasLabel = false;

        var reader = new ProtobufVarintReader(payload);
        while (!reader.End)
        {
            if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
            {
                return false;
            }

            if (wireType == ProtobufWireType.Varint)
            {
                if (!reader.TryReadVarint(out ulong value) || value > uint.MaxValue)
                {
                    return false;
                }

                if (fieldNumber == 1)
                {
                    label = (uint)value;
                    hasLabel = true;
                }
                else if (fieldNumber == 2)
                {
                    epoch = (uint)value;
                }

                continue;
            }

            if (!reader.TrySkipField(wireType))
            {
                return false;
            }
        }

        if (!hasLabel)
        {
            return false;
        }

        processId = new ProcessId(label, epoch);
        return true;
    }

    private static bool TryGetPayloadSpan(
        ReadOnlySequence<byte> payload,
        out byte[]? rented,
        out ReadOnlySpan<byte> span)
    {
        rented = null;
        span = default;

        if (payload.Length < 0 || payload.Length > MaxPayloadBytes)
        {
            return false;
        }

        if (payload.IsSingleSegment)
        {
            span = payload.FirstSpan;
            return true;
        }

        int length = (int)payload.Length;
        rented = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> destination = rented.AsSpan(0, length);
        payload.CopyTo(destination);
        span = destination;
        return true;
    }
}

internal enum GameUtilitiesCommandKind : byte
{
    Unknown = 0,
    RealmListTicketRequest = 1,
    RealmListRequest = 2,
    RealmJoinRequest = 3,
    LastCharPlayedRequest = 4,
    RealmJoinTicketRequest = 5
}

internal readonly record struct BnetGameUtilitiesRequestInfo(
    GameUtilitiesCommandKind Command,
    int AttributeCount,
    bool HasAccountId,
    bool HasGameAccountId,
    bool HasClientInfo,
    string RealmListSubRegion,
    uint RealmAddress,
    byte[]? ClientSecret32,
    int ClientInfoRawBytes,
    string? ClientInfoRawHeadHex,
    string? ClientInfoExtractDetails);

internal static class BnetGameUtilitiesPayloadParser
{
    private const int MaxPayloadBytes = 512 * 1024;

    private static readonly byte[] CommandRealmListTicketRequestPrefix = "Command_RealmListTicketRequest_v1"u8.ToArray();
    private static readonly byte[] CommandRealmListRequestPrefix = "Command_RealmListRequest_v1"u8.ToArray();
    private static readonly byte[] CommandRealmJoinRequestPrefix = "Command_RealmJoinRequest_v1"u8.ToArray();
    private static readonly byte[] CommandRealmJoinTicketRequestPrefix = "Command_RealmJoinTicketRequest_v1"u8.ToArray();
    private static readonly byte[] CommandLastCharPlayedRequestPrefix = "Command_LastCharPlayedRequest_v1"u8.ToArray();
    private static readonly byte[] ParamRealmAddressName = "Param_RealmAddress"u8.ToArray();
    private static readonly byte[] ParamClientInfoName = "Param_ClientInfo"u8.ToArray();

    public static bool TryReadClientRequestInfo(ReadOnlySequence<byte> payload, out BnetGameUtilitiesRequestInfo info)
    {
        GameUtilitiesCommandKind command = GameUtilitiesCommandKind.Unknown;
        int attributeCount = 0;
        bool hasAccountId = false;
        bool hasGameAccountId = false;
        bool hasClientInfo = false;
        string realmListSubRegion = string.Empty;
        uint realmAddress = 0;
        byte[]? clientSecret32 = null;
        int clientInfoRawBytes = 0;
        string? clientInfoRawHeadHex = null;
        string? clientInfoExtractDetails = null;

        if (!TryGetPayloadSpan(payload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            info = default;
            return false;
        }

        try
        {
            var reader = new ProtobufVarintReader(span);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    info = new BnetGameUtilitiesRequestInfo(
                        command,
                        attributeCount,
                        hasAccountId,
                        hasGameAccountId,
                        hasClientInfo,
                        realmListSubRegion,
                        realmAddress,
                        clientSecret32,
                        clientInfoRawBytes,
                        clientInfoRawHeadHex,
                        clientInfoExtractDetails);
                    return false;
                }

                if (fieldNumber == 1 && wireType == ProtobufWireType.LengthDelimited)
                {
                    attributeCount++;
                    if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> attributePayload))
                    {
                        info = new BnetGameUtilitiesRequestInfo(
                            command,
                            attributeCount,
                            hasAccountId,
                            hasGameAccountId,
                            hasClientInfo,
                            realmListSubRegion,
                            realmAddress,
                            clientSecret32,
                            clientInfoRawBytes,
                            clientInfoRawHeadHex,
                            clientInfoExtractDetails);
                        return false;
                    }

                    if (TryReadAttribute(
                            attributePayload,
                            out ReadOnlySpan<byte> attributeName,
                            out string attributeStringValue,
                            out bool hasUIntValue,
                            out ulong uintValue,
                            out byte[]? blobValue))
                    {
                        GameUtilitiesCommandKind parsed = ParseCommand(attributeName);
                        if (parsed != GameUtilitiesCommandKind.Unknown)
                        {
                            command = parsed;

                            if (parsed == GameUtilitiesCommandKind.RealmListRequest &&
                                !string.IsNullOrWhiteSpace(attributeStringValue))
                            {
                                realmListSubRegion = attributeStringValue;
                            }
                        }

                        if (attributeName.SequenceEqual(ParamRealmAddressName) &&
                            hasUIntValue &&
                            uintValue <= uint.MaxValue)
                        {
                            realmAddress = (uint)uintValue;
                        }

                        if (attributeName.SequenceEqual(ParamClientInfoName))
                        {
                            hasClientInfo = true;
                            if (blobValue is { Length: > 0 })
                            {
                                clientInfoRawBytes = blobValue.Length;
                                clientInfoRawHeadHex = ToHeadHex(blobValue, 64);

                                if (TryExtractClientSecret32(blobValue, out byte[] parsedClientSecret, out string extractDetails))
                                {
                                    clientSecret32 = parsedClientSecret;
                                    clientInfoExtractDetails = extractDetails;
                                }
                                else
                                {
                                    clientInfoExtractDetails = extractDetails;
                                }
                            }
                            else if (!string.IsNullOrWhiteSpace(attributeStringValue))
                            {
                                byte[] utf8 = Encoding.UTF8.GetBytes(attributeStringValue);
                                clientInfoRawBytes = utf8.Length;
                                clientInfoRawHeadHex = ToHeadHex(utf8, 64);

                                if (TryExtractClientSecret32(attributeStringValue, out byte[] parsedClientSecret, out string extractDetails))
                                {
                                    clientSecret32 = parsedClientSecret;
                                    clientInfoExtractDetails = extractDetails;
                                }
                                else
                                {
                                    clientInfoExtractDetails = extractDetails;
                                }
                            }
                            else
                            {
                                clientInfoRawBytes = 0;
                                clientInfoRawHeadHex = string.Empty;
                                clientInfoExtractDetails = "client-info-empty";
                            }
                        }
                    }

                    continue;
                }

                if (fieldNumber == 3 && wireType == ProtobufWireType.LengthDelimited)
                {
                    hasAccountId = true;
                    if (!reader.TrySkipLengthDelimited())
                    {
                        info = new BnetGameUtilitiesRequestInfo(
                            command,
                            attributeCount,
                            hasAccountId,
                            hasGameAccountId,
                            hasClientInfo,
                            realmListSubRegion,
                            realmAddress,
                            clientSecret32,
                            clientInfoRawBytes,
                            clientInfoRawHeadHex,
                            clientInfoExtractDetails);
                        return false;
                    }

                    continue;
                }

                if (fieldNumber == 4 && wireType == ProtobufWireType.LengthDelimited)
                {
                    hasGameAccountId = true;
                    if (!reader.TrySkipLengthDelimited())
                    {
                        info = new BnetGameUtilitiesRequestInfo(
                            command,
                            attributeCount,
                            hasAccountId,
                            hasGameAccountId,
                            hasClientInfo,
                            realmListSubRegion,
                            realmAddress,
                            clientSecret32,
                            clientInfoRawBytes,
                            clientInfoRawHeadHex,
                            clientInfoExtractDetails);
                        return false;
                    }

                    continue;
                }

                if (fieldNumber == 6 && wireType == ProtobufWireType.LengthDelimited)
                {
                    hasClientInfo = true;
                    if (!reader.TrySkipLengthDelimited())
                    {
                        info = new BnetGameUtilitiesRequestInfo(
                            command,
                            attributeCount,
                            hasAccountId,
                            hasGameAccountId,
                            hasClientInfo,
                            realmListSubRegion,
                            realmAddress,
                            clientSecret32,
                            clientInfoRawBytes,
                            clientInfoRawHeadHex,
                            clientInfoExtractDetails);
                        return false;
                    }

                    continue;
                }

                if (!reader.TrySkipField(wireType))
                {
                    info = new BnetGameUtilitiesRequestInfo(
                        command,
                        attributeCount,
                        hasAccountId,
                        hasGameAccountId,
                        hasClientInfo,
                        realmListSubRegion,
                        realmAddress,
                        clientSecret32,
                        clientInfoRawBytes,
                        clientInfoRawHeadHex,
                        clientInfoExtractDetails);
                    return false;
                }
            }

            info = new BnetGameUtilitiesRequestInfo(
                command,
                attributeCount,
                hasAccountId,
                hasGameAccountId,
                hasClientInfo,
                realmListSubRegion,
                realmAddress,
                clientSecret32,
                clientInfoRawBytes,
                clientInfoRawHeadHex,
                clientInfoExtractDetails);
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public static bool TryReadGetAllValuesForAttributeRequest(ReadOnlySequence<byte> payload, out BnetGetAllValuesRequestInfo info)
    {
        string attributeKey = string.Empty;
        uint program = 0;
        bool hasAgentId = false;

        if (!TryGetPayloadSpan(payload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            info = default;
            return false;
        }

        try
        {
            var reader = new ProtobufVarintReader(span);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
                    return false;
                }

                if (fieldNumber == 1 && wireType == ProtobufWireType.LengthDelimited)
                {
                    if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> bytes))
                    {
                        info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
                        return false;
                    }

                    attributeKey = Encoding.UTF8.GetString(bytes);
                    continue;
                }

                if (fieldNumber == 2 && wireType == ProtobufWireType.LengthDelimited)
                {
                    hasAgentId = true;
                    if (!reader.TrySkipLengthDelimited())
                    {
                        info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
                        return false;
                    }

                    continue;
                }

                if (fieldNumber == 5 && wireType == ProtobufWireType.Fixed32)
                {
                    if (!reader.TryReadFixed32(out program))
                    {
                        info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
                        return false;
                    }

                    continue;
                }

                if (fieldNumber == 5 && wireType == ProtobufWireType.Varint)
                {
                    if (!reader.TryReadVarint(out ulong rawProgram) || rawProgram > uint.MaxValue)
                    {
                        info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
                        return false;
                    }

                    program = (uint)rawProgram;
                    continue;
                }

                if (!reader.TrySkipField(wireType))
                {
                    info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
                    return false;
                }
            }

            info = new BnetGetAllValuesRequestInfo(attributeKey, program, hasAgentId);
            return true;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private static bool TryReadAttribute(
        ReadOnlySpan<byte> attributePayload,
        out ReadOnlySpan<byte> attributeName,
        out string stringValue,
        out bool hasUIntValue,
        out ulong uintValue,
        out byte[]? blobValue)
    {
        attributeName = default;
        stringValue = string.Empty;
        hasUIntValue = false;
        uintValue = 0;
        blobValue = null;
        bool hasName = false;

        var reader = new ProtobufVarintReader(attributePayload);
        while (!reader.End)
        {
            if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
            {
                return false;
            }

            if (fieldNumber == 1 && wireType == ProtobufWireType.LengthDelimited)
            {
                if (!reader.TryReadLengthDelimitedSpan(out attributeName))
                {
                    return false;
                }

                hasName = true;
                continue;
            }

            if (fieldNumber == 2 && wireType == ProtobufWireType.LengthDelimited)
            {
                if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> variantPayload))
                {
                    return false;
                }

                _ = TryReadVariantValues(variantPayload, out stringValue, out hasUIntValue, out uintValue, out blobValue);
                continue;
            }

            if (!reader.TrySkipField(wireType))
            {
                return false;
            }
        }

        return hasName;
    }

    private static bool TryReadVariantValues(
        ReadOnlySpan<byte> variantPayload,
        out string stringValue,
        out bool hasUIntValue,
        out ulong uintValue,
        out byte[]? blobValue)
    {
        stringValue = string.Empty;
        hasUIntValue = false;
        uintValue = 0;
        blobValue = null;
        bool hasAny = false;

        var reader = new ProtobufVarintReader(variantPayload);
        while (!reader.End)
        {
            if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
            {
                return false;
            }

            if (fieldNumber == 5 && wireType == ProtobufWireType.LengthDelimited)
            {
                if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> stringPayload))
                {
                    return false;
                }

                stringValue = Encoding.UTF8.GetString(stringPayload);
                hasAny = true;
                continue;
            }

            if (fieldNumber == 9 && wireType == ProtobufWireType.Varint)
            {
                if (!reader.TryReadVarint(out uintValue))
                {
                    return false;
                }

                hasUIntValue = true;
                hasAny = true;
                continue;
            }

            if (fieldNumber == 6 && wireType == ProtobufWireType.LengthDelimited)
            {
                if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> blobPayload))
                {
                    return false;
                }

                blobValue = blobPayload.ToArray();
                hasAny = true;
                continue;
            }

            if (wireType == ProtobufWireType.LengthDelimited)
            {
                if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> unknownPayload))
                {
                    return false;
                }

                // Keep first unknown length-delimited variant payload as fallback source.
                blobValue ??= unknownPayload.ToArray();
                hasAny = true;
                continue;
            }

            if (!reader.TrySkipField(wireType))
            {
                return false;
            }
        }

        return hasAny;
    }

    private static bool TryExtractClientSecret32(ReadOnlySpan<byte> clientInfoBlob, out byte[] clientSecret32, out string details)
    {
        clientSecret32 = Array.Empty<byte>();
        details = "blob-empty";
        if (clientInfoBlob.IsEmpty)
        {
            return false;
        }

        if (clientInfoBlob.Length == 32 && IsLikelySecretBytes(clientInfoBlob))
        {
            clientSecret32 = clientInfoBlob.ToArray();
            details = "raw32";
            return true;
        }

        string textDetails;
        if (TryExtractClientSecret32(Encoding.UTF8.GetString(clientInfoBlob), out clientSecret32, out textDetails))
        {
            details = $"text:{textDetails}";
            return true;
        }

        if (TryExtractClientSecret32FromBinaryProtobuf(clientInfoBlob, out clientSecret32, out string protobufDetails))
        {
            details = protobufDetails;
            return true;
        }

        details = $"extract-failed:text={textDetails};protobuf={protobufDetails}";
        return false;
    }

    private static bool TryExtractClientSecret32(string raw, out byte[] clientSecret32, out string details)
    {
        clientSecret32 = Array.Empty<byte>();
        details = "text-empty";
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        string trimmed = raw.Trim();
        if (TryDecodeBase64(trimmed, out byte[] base64Bytes) && base64Bytes.Length == 32)
        {
            clientSecret32 = base64Bytes;
            details = "raw-base64-32";
            return true;
        }

        if (TryDecodeHex(trimmed, out byte[] hexBytes) && hexBytes.Length == 32)
        {
            clientSecret32 = hexBytes;
            details = "raw-hex-32";
            return true;
        }

        byte[] utf8Raw = Encoding.UTF8.GetBytes(trimmed);
        if (utf8Raw.Length == 32)
        {
            clientSecret32 = utf8Raw;
            details = "raw-utf8-32";
            return true;
        }

        int prefixSeparator = raw.IndexOf(':');
        string jsonPayload = prefixSeparator >= 0 && prefixSeparator + 1 < raw.Length
            ? raw[(prefixSeparator + 1)..]
            : raw;

        try
        {
            using var document = JsonDocument.Parse(jsonPayload);
            if (TryFindJsonPropertyCaseInsensitive(document.RootElement, "secret", out JsonElement secretElement))
            {
                bool decoded = TryDecodeSecretElement(secretElement, out clientSecret32);
                details = decoded ? "json-secret-decoded" : "json-secret-invalid";
                if (decoded)
                {
                    return true;
                }
            }

            if (TryFindAnyJsonSecretCandidate(document.RootElement, out clientSecret32, out string candidatePath, out string candidateKind, out string candidateMeta))
            {
                details = $"json-candidate:{candidateKind}@{candidatePath}:{candidateMeta}";
                return true;
            }

            details = "json-no-32-byte-candidate";
            return false;
        }
        catch (JsonException)
        {
            if (TryExtractFirstJsonObject(jsonPayload, out string isolatedJson))
            {
                try
                {
                    using var isolated = JsonDocument.Parse(isolatedJson);

                    if (TryFindJsonPropertyCaseInsensitive(isolated.RootElement, "secret", out JsonElement isolatedSecret))
                    {
                        bool decoded = TryDecodeSecretElement(isolatedSecret, out clientSecret32);
                        details = decoded ? "json-isolated-secret-decoded" : "json-isolated-secret-invalid";
                        if (decoded)
                        {
                            return true;
                        }
                    }

                    if (TryFindAnyJsonSecretCandidate(isolated.RootElement, out clientSecret32, out string candidatePath, out string candidateKind, out string candidateMeta))
                    {
                        details = $"json-isolated-candidate:{candidateKind}@{candidatePath}:{candidateMeta}";
                        return true;
                    }

                    details = "json-isolated-no-32-byte-candidate";
                    return false;
                }
                catch (JsonException)
                {
                    details = "json-parse-failed";
                    return false;
                }
            }

            details = "json-parse-failed";
            return false;
        }
    }

    private static bool TryExtractFirstJsonObject(string text, out string jsonObject)
    {
        jsonObject = string.Empty;
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        int start = text.IndexOf('{');
        if (start < 0 || start >= text.Length)
        {
            return false;
        }

        int depth = 0;
        bool inString = false;
        bool escape = false;

        for (int i = start; i < text.Length; i++)
        {
            char c = text[i];
            if (inString)
            {
                if (escape)
                {
                    escape = false;
                    continue;
                }

                if (c == '\\')
                {
                    escape = true;
                    continue;
                }

                if (c == '"')
                {
                    inString = false;
                }

                continue;
            }

            if (c == '"')
            {
                inString = true;
                continue;
            }

            if (c == '{')
            {
                depth++;
                continue;
            }

            if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    jsonObject = text.Substring(start, i - start + 1);
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryExtractClientSecret32FromBinaryProtobuf(
        ReadOnlySpan<byte> payload,
        out byte[] clientSecret32,
        out string details)
    {
        clientSecret32 = Array.Empty<byte>();
        details = "protobuf-no-candidate";
        if (payload.IsEmpty)
        {
            details = "protobuf-empty";
            return false;
        }

        var queue = new Queue<(byte[] Data, string Path, int Depth)>();
        queue.Enqueue((payload.ToArray(), "root", 0));

        byte[]? bestCandidate = null;
        string bestPath = string.Empty;
        int bestScore = int.MinValue;
        int secondScore = int.MinValue;
        int candidateCount = 0;

        while (queue.Count > 0)
        {
            (byte[] data, string path, int depth) = queue.Dequeue();
            if (depth > 5 || data.Length == 0)
            {
                continue;
            }

            var reader = new ProtobufVarintReader(data);
            while (!reader.End)
            {
                if (!reader.TryReadFieldHeader(out uint fieldNumber, out ProtobufWireType wireType))
                {
                    break;
                }

                if (wireType == ProtobufWireType.LengthDelimited)
                {
                    if (!reader.TryReadLengthDelimitedSpan(out ReadOnlySpan<byte> fieldPayload))
                    {
                        break;
                    }

                    string fieldPath = $"{path}/{fieldNumber}";

                    if (fieldPayload.Length == 32 && IsLikelySecretBytes(fieldPayload))
                    {
                        int score = ScoreSecretCandidate(fieldPayload, depth, fieldNumber);
                        candidateCount++;
                        if (score > bestScore)
                        {
                            secondScore = bestScore;
                            bestScore = score;
                            bestCandidate = fieldPayload.ToArray();
                            bestPath = fieldPath;
                        }
                        else if (score > secondScore)
                        {
                            secondScore = score;
                        }
                    }

                    if (depth < 5 &&
                        fieldPayload.Length >= 2 &&
                        fieldPayload.Length <= 1024 &&
                        LooksLikeProtobufMessage(fieldPayload))
                    {
                        queue.Enqueue((fieldPayload.ToArray(), fieldPath, depth + 1));
                    }

                    continue;
                }

                if (!reader.TrySkipField(wireType))
                {
                    break;
                }
            }
        }

        if (bestCandidate is null)
        {
            details = "protobuf-no-candidate";
            return false;
        }

        if (candidateCount > 1 && (bestScore - secondScore) < 2)
        {
            details = $"protobuf-ambiguous:candidates={candidateCount},bestScore={bestScore},secondScore={secondScore},bestPath={bestPath}";
            return false;
        }

        clientSecret32 = bestCandidate;
        details = $"protobuf-candidate:candidates={candidateCount},path={bestPath},score={bestScore}";
        return true;
    }

    private static bool LooksLikeProtobufMessage(ReadOnlySpan<byte> payload)
    {
        var reader = new ProtobufVarintReader(payload);
        int fields = 0;
        while (!reader.End && fields < 8)
        {
            if (!reader.TryReadFieldHeader(out _, out ProtobufWireType wireType))
            {
                return false;
            }

            fields++;
            if (!reader.TrySkipField(wireType))
            {
                return false;
            }
        }

        return fields > 0;
    }

    private static bool IsLikelySecretBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32)
        {
            return false;
        }

        bool allZero = true;
        int printable = 0;
        Span<byte> seen = stackalloc byte[256];
        int unique = 0;

        foreach (byte b in bytes)
        {
            if (b != 0)
            {
                allZero = false;
            }

            if (b >= 0x20 && b <= 0x7E)
            {
                printable++;
            }

            if (seen[b] == 0)
            {
                seen[b] = 1;
                unique++;
            }
        }

        if (allZero)
        {
            return false;
        }

        if (unique < 10)
        {
            return false;
        }

        // Reject likely plain-text tokens.
        return printable < 28;
    }

    private static int ScoreSecretCandidate(ReadOnlySpan<byte> bytes, int depth, uint fieldNumber)
    {
        int printable = 0;
        Span<byte> seen = stackalloc byte[256];
        int unique = 0;

        foreach (byte b in bytes)
        {
            if (b >= 0x20 && b <= 0x7E)
            {
                printable++;
            }

            if (seen[b] == 0)
            {
                seen[b] = 1;
                unique++;
            }
        }

        int score = unique;
        score += (32 - printable);
        score += depth <= 2 ? 6 : 0;
        score += fieldNumber <= 4 ? 4 : 0;
        return score;
    }

    private static bool TryFindAnyJsonSecretCandidate(
        JsonElement root,
        out byte[] clientSecret32,
        out string candidatePath,
        out string candidateKind,
        out string candidateMeta)
    {
        clientSecret32 = Array.Empty<byte>();
        candidatePath = "$";
        candidateKind = "none";
        candidateMeta = "none";

        var candidates = new List<(int Score, byte[] Bytes, string Path, string Kind, string Meta)>(8);
        CollectJsonSecretCandidates(root, "$", string.Empty, candidates);

        if (candidates.Count == 0)
        {
            return false;
        }

        candidates.Sort(static (a, b) => b.Score.CompareTo(a.Score));
        var best = candidates[0];
        if (candidates.Count > 1 && (best.Score - candidates[1].Score) <= 0)
        {
            candidateMeta = $"ambiguous:best={best.Score},second={candidates[1].Score},count={candidates.Count}";
            return false;
        }

        clientSecret32 = best.Bytes;
        candidatePath = best.Path;
        candidateKind = best.Kind;
        candidateMeta = $"score={best.Score}";
        return true;
    }

    private static void CollectJsonSecretCandidates(
        JsonElement element,
        string path,
        string propertyName,
        List<(int Score, byte[] Bytes, string Path, string Kind, string Meta)> candidates)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    string childPath = $"{path}.{property.Name}";
                    CollectJsonSecretCandidates(property.Value, childPath, property.Name, candidates);
                }

                break;
            }
            case JsonValueKind.Array:
            {
                if (TryDecodeSecretElement(element, out byte[] arraySecret) && IsLikelySecretBytes(arraySecret))
                {
                    int score = ScoreJsonCandidate(arraySecret, propertyName, path, decodeKind: "json-array32");
                    candidates.Add((score, arraySecret, path, "json-array32", $"property={propertyName}"));
                }

                int index = 0;
                foreach (JsonElement item in element.EnumerateArray())
                {
                    CollectJsonSecretCandidates(item, $"{path}[{index}]", propertyName, candidates);
                    index++;
                }

                break;
            }
            case JsonValueKind.String:
            {
                string text = element.GetString() ?? string.Empty;
                if (TryDecodePotentialSecretString(text, out byte[] decoded, out string decodeKind) &&
                    IsLikelySecretBytes(decoded))
                {
                    int score = ScoreJsonCandidate(decoded, propertyName, path, decodeKind);
                    candidates.Add((score, decoded, path, decodeKind, $"property={propertyName}"));
                }

                break;
            }
            default:
                break;
        }
    }

    private static bool TryDecodePotentialSecretString(string text, out byte[] data, out string decodeKind)
    {
        data = Array.Empty<byte>();
        decodeKind = "none";
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string trimmed = text.Trim();
        if (TryDecodeBase64(trimmed, out byte[] base64Bytes) && base64Bytes.Length == 32)
        {
            data = base64Bytes;
            decodeKind = "json-base64";
            return true;
        }

        if (TryDecodeHex(trimmed, out byte[] hexBytes) && hexBytes.Length == 32)
        {
            data = hexBytes;
            decodeKind = "json-hex";
            return true;
        }

        byte[] utf8 = Encoding.UTF8.GetBytes(trimmed);
        if (utf8.Length == 32)
        {
            data = utf8;
            decodeKind = "json-utf8-32";
            return true;
        }

        return false;
    }

    private static int ScoreJsonCandidate(ReadOnlySpan<byte> bytes, string propertyName, string path, string decodeKind)
    {
        int score = 0;
        score += ScoreSecretCandidate(bytes, depth: 0, fieldNumber: 1);

        string p = propertyName.ToLowerInvariant();
        string full = path.ToLowerInvariant();
        if (p.Contains("secret") || full.Contains("secret"))
        {
            score += 40;
        }

        if (p.Contains("client") || full.Contains("client"))
        {
            score += 10;
        }

        if (p.Contains("join") || full.Contains("join"))
        {
            score += 8;
        }

        if (p.Contains("key") || full.Contains("key"))
        {
            score += 8;
        }

        if (decodeKind == "json-base64" || decodeKind == "json-hex")
        {
            score += 6;
        }

        return score;
    }

    private static string ToHeadHex(ReadOnlySpan<byte> bytes, int maxBytes)
    {
        if (bytes.IsEmpty || maxBytes <= 0)
        {
            return string.Empty;
        }

        int take = Math.Min(bytes.Length, maxBytes);
        return Convert.ToHexString(bytes[..take]);
    }

    private static bool TryFindJsonPropertyCaseInsensitive(JsonElement root, string propertyName, out JsonElement value)
    {
        value = default;

        if (root.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }

                if (TryFindJsonPropertyCaseInsensitive(property.Value, propertyName, out value))
                {
                    return true;
                }
            }
        }
        else if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in root.EnumerateArray())
            {
                if (TryFindJsonPropertyCaseInsensitive(item, propertyName, out value))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryDecodeSecretElement(JsonElement secretElement, out byte[] clientSecret32)
    {
        clientSecret32 = Array.Empty<byte>();

        switch (secretElement.ValueKind)
        {
            case JsonValueKind.String:
            {
                string secretText = secretElement.GetString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(secretText))
                {
                    return false;
                }

                if (TryDecodeBase64(secretText, out byte[] base64Bytes) && base64Bytes.Length == 32)
                {
                    clientSecret32 = base64Bytes;
                    return true;
                }

                if (TryDecodeHex(secretText, out byte[] hexBytes) && hexBytes.Length == 32)
                {
                    clientSecret32 = hexBytes;
                    return true;
                }

                byte[] utf8Bytes = Encoding.UTF8.GetBytes(secretText);
                if (utf8Bytes.Length == 32)
                {
                    clientSecret32 = utf8Bytes;
                    return true;
                }

                return false;
            }
            case JsonValueKind.Array:
            {
                Span<byte> bytes = stackalloc byte[32];
                int index = 0;
                foreach (JsonElement item in secretElement.EnumerateArray())
                {
                    if (index >= bytes.Length || item.ValueKind != JsonValueKind.Number || !item.TryGetByte(out byte value))
                    {
                        return false;
                    }

                    bytes[index++] = value;
                }

                if (index != 32)
                {
                    return false;
                }

                clientSecret32 = bytes.ToArray();
                return true;
            }
            case JsonValueKind.Object:
            {
                if (TryFindJsonPropertyCaseInsensitive(secretElement, "value", out JsonElement nested))
                {
                    return TryDecodeSecretElement(nested, out clientSecret32);
                }

                return false;
            }
            default:
                return false;
        }
    }

    private static bool TryDecodeBase64(string text, out byte[] data)
    {
        data = Array.Empty<byte>();
        try
        {
            data = Convert.FromBase64String(text);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool TryDecodeHex(string text, out byte[] data)
    {
        data = Array.Empty<byte>();
        if (text.Length % 2 != 0)
        {
            return false;
        }

        try
        {
            data = Convert.FromHexString(text);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static GameUtilitiesCommandKind ParseCommand(ReadOnlySpan<byte> attributeName)
    {
        if (attributeName.StartsWith(CommandRealmListTicketRequestPrefix))
        {
            return GameUtilitiesCommandKind.RealmListTicketRequest;
        }

        if (attributeName.StartsWith(CommandRealmListRequestPrefix))
        {
            return GameUtilitiesCommandKind.RealmListRequest;
        }

        if (attributeName.StartsWith(CommandRealmJoinRequestPrefix))
        {
            return GameUtilitiesCommandKind.RealmJoinRequest;
        }

        if (attributeName.StartsWith(CommandRealmJoinTicketRequestPrefix))
        {
            return GameUtilitiesCommandKind.RealmJoinTicketRequest;
        }

        if (attributeName.StartsWith(CommandLastCharPlayedRequestPrefix))
        {
            return GameUtilitiesCommandKind.LastCharPlayedRequest;
        }

        return GameUtilitiesCommandKind.Unknown;
    }

    private static bool TryGetPayloadSpan(
        ReadOnlySequence<byte> payload,
        out byte[]? rented,
        out ReadOnlySpan<byte> span)
    {
        rented = null;
        span = default;

        if (payload.Length < 0 || payload.Length > MaxPayloadBytes)
        {
            return false;
        }

        if (payload.IsSingleSegment)
        {
            span = payload.FirstSpan;
            return true;
        }

        int length = (int)payload.Length;
        rented = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> destination = rented.AsSpan(0, length);
        payload.CopyTo(destination);
        span = destination;
        return true;
    }
}

internal static class BnetGameUtilitiesPayloadFactory
{
    private const string RealmListAttributeKeyPrefix = "Command_RealmListRequest_v1";

    private static readonly byte[] RealmListTicketAttributeName = "Param_RealmListTicket"u8.ToArray();
    private static readonly byte[] RealmListTicketValue = "AuthRealmListTicket"u8.ToArray();
    private static readonly byte[] RealmListParamAttributeName = "Param_RealmList"u8.ToArray();
    private static readonly byte[] CharacterCountListParamAttributeName = "Param_CharacterCountList"u8.ToArray();
    private static readonly byte[] RealmJoinTicketParamAttributeName = "Param_RealmJoinTicket"u8.ToArray();
    private static readonly byte[] ServerAddressesParamAttributeName = "Param_ServerAddresses"u8.ToArray();
    private static readonly byte[] JoinSecretParamAttributeName = "Param_JoinSecret"u8.ToArray();
    private static readonly byte[] DefaultSubRegionValue = "1-1-0"u8.ToArray();
    private static readonly byte[] RegisterUtilitiesCiidValue = "adapter-auth-gw"u8.ToArray();
    private static readonly ReadOnlyMemory<byte> RealmListTicketResponsePayload = BuildRealmListTicketResponsePayload();
    private static readonly ReadOnlyMemory<byte> RealmListSubRegionValuesPayload = BuildRealmListSubRegionValuesPayload();

    public static ReadOnlyMemory<byte> GetClientResponsePayload(GameUtilitiesCommandKind command)
    {
        return command switch
        {
            GameUtilitiesCommandKind.RealmListTicketRequest => RealmListTicketResponsePayload,
            _ => ReadOnlyMemory<byte>.Empty
        };
    }

    public static ReadOnlyMemory<byte> RegisterUtilitiesResponsePayload { get; } = BuildRegisterUtilitiesResponsePayload();

    public static IReadOnlyList<RealmData> FallbackRealmList { get; } = new[]
    {
        new RealmData
        {
            Id = 1u,
            Name = "Adapter Realm",
            Address = "127.0.0.1",
            LocalAddress = "127.0.0.1",
            LocalSubnetMask = "255.255.255.0",
            Port = 8085,
            Icon = 0,
            Flag = 0,
            Timezone = 1,
            AllowedSecurityLevel = 0,
            Population = 0.5f,
            Gamebuild = 66102u,
            Region = 1,
            Battlegroup = 1
        }
    };

    public static RealmData SelectRealmForJoin(IReadOnlyList<RealmData> realms, uint requestedRealmAddress)
    {
        if (realms.Count == 0)
        {
            return FallbackRealmList[0];
        }

        if (requestedRealmAddress == 0)
        {
            return realms[0];
        }

        for (int i = 0; i < realms.Count; i++)
        {
            RealmData realm = realms[i];
            uint region = realm.Region == 0 ? 1u : realm.Region;
            uint battlegroup = realm.Battlegroup == 0 ? 1u : realm.Battlegroup;
            uint realmAddress = (region << 24) | (battlegroup << 16) | (realm.Id & 0xFFFFu);

            if (realmAddress == requestedRealmAddress)
            {
                return realm;
            }
        }

        return realms[0];
    }

    public static ReadOnlyMemory<byte> GetAllValuesForAttributeResponsePayload(string attributeKey)
    {
        if (!string.IsNullOrEmpty(attributeKey) &&
            attributeKey.StartsWith(RealmListAttributeKeyPrefix, StringComparison.Ordinal))
        {
            return RealmListSubRegionValuesPayload;
        }

        return ReadOnlyMemory<byte>.Empty;
    }

    public static ReadOnlyMemory<byte> BuildRealmListResponsePayload(
        ReadOnlySpan<byte> realmListPayload,
        ReadOnlySpan<byte> characterCountPayload)
    {
        // ClientResponse.attribute[]:
        // - Param_RealmList (compressed JSONRealmListUpdates blob)
        // - Param_CharacterCountList (compressed JSONRealmCharacterCountList blob)
        int capacity = Math.Max(192, realmListPayload.Length + characterCountPayload.Length + 192);
        var responsePayload = new ArrayBufferWriter<byte>(capacity);
        var responseWriter = new ProtobufWriter(responsePayload);
        WriteAttributeBlob(ref responseWriter, RealmListParamAttributeName, realmListPayload);
        WriteAttributeBlob(ref responseWriter, CharacterCountListParamAttributeName, characterCountPayload);
        return responsePayload.WrittenSpan.ToArray();
    }

    public static ReadOnlyMemory<byte> BuildRealmJoinResponsePayload(
        ReadOnlySpan<byte> serverAddressesPayload,
        int accountId,
        string gameAccountName,
        uint platformType,
        uint clientType,
        uint clientArch,
        ReadOnlySpan<byte> joinSecret)
    {
        // Trinity-compatible JoinRealm response:
        // Param_RealmJoinTicket = JSON serialized RealmJoinTicket
        // Param_ServerAddresses = compressed JSONRealmListServerIPAddresses blob
        // Param_JoinSecret = 32-byte server secret
        byte[] joinTicket = BuildRealmJoinTicketJson(accountId, gameAccountName, platformType, clientType, clientArch);

        var responsePayload = new ArrayBufferWriter<byte>(Math.Max(160, serverAddressesPayload.Length + 160));
        var responseWriter = new ProtobufWriter(responsePayload);
        WriteAttributeBlob(ref responseWriter, RealmJoinTicketParamAttributeName, joinTicket);
        WriteAttributeBlob(ref responseWriter, ServerAddressesParamAttributeName, serverAddressesPayload);
        WriteAttributeBlob(ref responseWriter, JoinSecretParamAttributeName, joinSecret);
        return responsePayload.WrittenSpan.ToArray();
    }

    private static byte[] BuildRealmListTicketResponsePayload()
    {
        // ClientResponse.attribute[0] = Attribute("Param_RealmListTicket", Variant.blob_value="AuthRealmListTicket")
        var variantPayload = new ArrayBufferWriter<byte>(64);
        var variantWriter = new ProtobufWriter(variantPayload);
        variantWriter.WriteTag(fieldNumber: 6, wireType: 2); // Variant.blob_value
        variantWriter.WriteLengthPrefixedBytes(RealmListTicketValue);

        var attributePayload = new ArrayBufferWriter<byte>(128);
        var attributeWriter = new ProtobufWriter(attributePayload);
        attributeWriter.WriteTag(fieldNumber: 1, wireType: 2); // Attribute.name
        attributeWriter.WriteLengthPrefixedBytes(RealmListTicketAttributeName);
        attributeWriter.WriteTag(fieldNumber: 2, wireType: 2); // Attribute.value
        attributeWriter.WriteLengthPrefixedBytes(variantPayload.WrittenSpan);

        var responsePayload = new ArrayBufferWriter<byte>(160);
        var responseWriter = new ProtobufWriter(responsePayload);
        responseWriter.WriteTag(fieldNumber: 1, wireType: 2); // ClientResponse.attribute
        responseWriter.WriteLengthPrefixedBytes(attributePayload.WrittenSpan);

        return responsePayload.WrittenSpan.ToArray();
    }

    private static byte[] BuildRealmListSubRegionValuesPayload()
    {
        // GetAllValuesForAttributeResponse.attribute_value[0] = Variant.string_value("1-1-0")
        var variantPayload = new ArrayBufferWriter<byte>(32);
        var variantWriter = new ProtobufWriter(variantPayload);
        variantWriter.WriteTag(fieldNumber: 5, wireType: 2); // Variant.string_value
        variantWriter.WriteLengthPrefixedBytes(DefaultSubRegionValue);

        var responsePayload = new ArrayBufferWriter<byte>(48);
        var responseWriter = new ProtobufWriter(responsePayload);
        responseWriter.WriteTag(fieldNumber: 1, wireType: 2); // attribute_value
        responseWriter.WriteLengthPrefixedBytes(variantPayload.WrittenSpan);

        return responsePayload.WrittenSpan.ToArray();
    }

    private static byte[] BuildRegisterUtilitiesResponsePayload()
    {
        // RegisterUtilitiesResponse.ciid = "adapter-auth-gw"
        var responsePayload = new ArrayBufferWriter<byte>(32);
        var writer = new ProtobufWriter(responsePayload);
        writer.WriteTag(fieldNumber: 1, wireType: 2);
        writer.WriteLengthPrefixedBytes(RegisterUtilitiesCiidValue);
        return responsePayload.WrittenSpan.ToArray();
    }

    private static void WriteAttributeBlob(ref ProtobufWriter responseWriter, ReadOnlySpan<byte> attributeName, ReadOnlySpan<byte> blobValue)
    {
        var variantPayload = new ArrayBufferWriter<byte>(Math.Max(16, blobValue.Length + 8));
        var variantWriter = new ProtobufWriter(variantPayload);
        variantWriter.WriteTag(fieldNumber: 6, wireType: 2); // Variant.blob_value
        variantWriter.WriteLengthPrefixedBytes(blobValue);

        var attributePayload = new ArrayBufferWriter<byte>(Math.Max(32, attributeName.Length + variantPayload.WrittenCount + 16));
        var attributeWriter = new ProtobufWriter(attributePayload);
        attributeWriter.WriteTag(fieldNumber: 1, wireType: 2); // Attribute.name
        attributeWriter.WriteLengthPrefixedBytes(attributeName);
        attributeWriter.WriteTag(fieldNumber: 2, wireType: 2); // Attribute.value
        attributeWriter.WriteLengthPrefixedBytes(variantPayload.WrittenSpan);

        responseWriter.WriteTag(fieldNumber: 1, wireType: 2); // ClientResponse.attribute
        responseWriter.WriteLengthPrefixedBytes(attributePayload.WrittenSpan);
    }

    private static byte[] BuildRealmJoinTicketJson(
        int accountId,
        string gameAccountName,
        uint platformType,
        uint clientType,
        uint clientArch)
    {
        string account = string.IsNullOrWhiteSpace(gameAccountName) ? "AIMAYA" : gameAccountName.Trim();
        int normalizedAccountId = accountId > 0 ? accountId : 0;

        var buffer = new ArrayBufferWriter<byte>(Math.Max(96, account.Length + 80));
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteNumber("accountId", normalizedAccountId);
        writer.WriteString("gameAccount", account);
        writer.WriteNumber("platform", platformType);
        writer.WriteNumber("type", clientType);
        writer.WriteNumber("clientArch", clientArch);
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }
}

public sealed class CmsgAuthSessionHandler : IAuthHandler
{
    private readonly ILogger<CmsgAuthSessionHandler> _logger;
    private readonly IDatabaseService _databaseService;
    private readonly IAuthSessionManager _sessionManager;
    private readonly ISrp6Calculator _srp6;

    public CmsgAuthSessionHandler(
        ILogger<CmsgAuthSessionHandler> logger,
        IDatabaseService databaseService,
        IAuthSessionManager sessionManager,
        ISrp6Calculator srp6)
    {
        _logger = logger;
        _databaseService = databaseService;
        _sessionManager = sessionManager;
        _srp6 = srp6;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (!AuthPayloadParser.TryParseAuthSession(payload, out RetailAuthSessionPacket authPacket))
        {
            _logger.LogWarning(
                "Malformed CMSG_AUTH_SESSION packet. ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}. Disconnecting.",
                context.ConnectionId,
                payload.Length);
            return AuthDispatchResult.Disconnect;
        }

        AccountData? account = await _databaseService.GetAccountData(authPacket.Username, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            await context.SendPacketAsync(
                Retail1201AuthOpcodes.SmsgAuthResponse,
                AuthPayloadFactory.CreateFailure(BridgeAuthStatus.UnknownAccount),
                cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "Unknown account '{Username}' (Protocol={Protocol}, Build={Build}, OS={OS}, Arch={Arch}). ConnectionId={ConnectionId}",
                authPacket.Username,
                authPacket.ProtocolVersion,
                authPacket.ClientBuild,
                authPacket.OperatingSystem,
                authPacket.Architecture,
                context.ConnectionId);

            return AuthDispatchResult.Continue;
        }

        Srp6ServerChallenge challenge = _srp6.CreateServerChallenge(account.Salt, account.Verifier);
        _sessionManager.CreateOrReplace(
            context.ConnectionId,
            account.Id,
            account.Username,
            account.Salt,
            account.Verifier,
            challenge.ServerPublicB,
            challenge.ServerPrivateb);

        if (!AuthPayloadFactory.TryCreateSrp6Challenge(
                challenge.ServerPublicB,
                challenge.Salt,
                _srp6.Generator.Span,
                _srp6.Modulus.Span,
                out byte[] challengePayload))
        {
            _logger.LogWarning(
                "Failed to build SRP6 challenge payload. ConnectionId={ConnectionId}",
                context.ConnectionId);
            return AuthDispatchResult.Disconnect;
        }

        await context.SendPacketAsync(
            Retail1201AuthOpcodes.SmsgAuthChallenge,
            challengePayload,
            cancellationToken).ConfigureAwait(false);

        _logger.LogInformation(
            "SRP6 challenge emitted for '{Username}' (Protocol={Protocol}, Build={Build}, OS={OS}, Arch={Arch}). ConnectionId={ConnectionId}",
            authPacket.Username,
            authPacket.ProtocolVersion,
            authPacket.ClientBuild,
            authPacket.OperatingSystem,
            authPacket.Architecture,
            context.ConnectionId);

        return AuthDispatchResult.Continue;
    }
}

public sealed class CmsgAuthContinuedSessionHandler : IAuthHandler
{
    private readonly ILogger<CmsgAuthContinuedSessionHandler> _logger;

    public CmsgAuthContinuedSessionHandler(ILogger<CmsgAuthContinuedSessionHandler> logger)
    {
        _logger = logger;
    }

    public ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "Continued-session packet received (ServiceId={ServiceId}, MethodId={MethodId}, Token={Token}). ConnectionId={ConnectionId}",
            serviceId,
            methodId,
            token,
            context.ConnectionId);

        return ValueTask.FromResult(AuthDispatchResult.Continue);
    }
}

public sealed class RealmListRequestHandler : IAuthHandler
{
    private readonly ILogger<RealmListRequestHandler> _logger;
    private readonly IDatabaseService _databaseService;
    private readonly IAuthSessionManager _sessionManager;

    public RealmListRequestHandler(
        ILogger<RealmListRequestHandler> logger,
        IDatabaseService databaseService,
        IAuthSessionManager sessionManager)
    {
        _logger = logger;
        _databaseService = databaseService;
        _sessionManager = sessionManager;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        if (!_sessionManager.TryGet(context.ConnectionId, out AuthSession? session) ||
            session.State != AuthSessionState.Authenticated)
        {
            _logger.LogWarning(
                "Realm list requested before authentication. ConnectionId={ConnectionId}, ServiceId={ServiceId}, MethodId={MethodId}",
                context.ConnectionId,
                serviceId,
                methodId);
            return AuthDispatchResult.Disconnect;
        }

        IReadOnlyList<RealmData> realms = await _databaseService
            .GetWorldList(cancellationToken)
            .ConfigureAwait(false);

        if (!RealmListPacketBuilder.TryBuildRetailPayload(realms, out ArrayBufferWriter<byte> writer))
        {
            _logger.LogWarning(
                "Failed to build SMSG_REALM_LIST payload. ConnectionId={ConnectionId}",
                context.ConnectionId);
            return AuthDispatchResult.Disconnect;
        }

        await context.SendPacketAsync(
            Retail1201AuthOpcodes.SmsgRealmList,
            writer.WrittenMemory,
            cancellationToken).ConfigureAwait(false);

        _logger.LogInformation(
            "SMSG_REALM_LIST sent. ConnectionId={ConnectionId}, RealmCount={RealmCount}",
            context.ConnectionId,
            realms.Count);

        return AuthDispatchResult.Continue;
    }
}

public sealed class BattleNetRequestHandler : IAuthHandler
{
    private readonly ILogger<BattleNetRequestHandler> _logger;
    private readonly RealmListRequestHandler _realmListRequestHandler;

    public BattleNetRequestHandler(
        ILogger<BattleNetRequestHandler> logger,
        RealmListRequestHandler realmListRequestHandler)
    {
        _logger = logger;
        _realmListRequestHandler = realmListRequestHandler;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug(
            "Battle.net request packet received (ServiceId={ServiceId}, MethodId={MethodId}, Token={Token}). ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}",
            serviceId,
            methodId,
            token,
            context.ConnectionId,
            payload.Length);

        if (AuthPayloadParser.IsLikelyRealmListRequest(payload))
        {
            return await _realmListRequestHandler
                .HandleAsync(context, serviceId, methodId, token, payload, cancellationToken)
                .ConfigureAwait(false);
        }

        return AuthDispatchResult.Continue;
    }
}

public sealed class BattleNetChallengeResponseHandler : IAuthHandler
{
    private readonly ILogger<BattleNetChallengeResponseHandler> _logger;
    private readonly IDatabaseService _databaseService;
    private readonly IAuthSessionManager _sessionManager;
    private readonly ISrp6Calculator _srp6;

    public BattleNetChallengeResponseHandler(
        ILogger<BattleNetChallengeResponseHandler> logger,
        IDatabaseService databaseService,
        IAuthSessionManager sessionManager,
        ISrp6Calculator srp6)
    {
        _logger = logger;
        _databaseService = databaseService;
        _sessionManager = sessionManager;
        _srp6 = srp6;
    }

    public async ValueTask<AuthDispatchResult> HandleAsync(
        AuthPacketContext context,
        uint serviceId,
        uint methodId,
        uint token,
        ReadOnlySequence<byte> payload,
        CancellationToken cancellationToken)
    {
        Span<byte> clientPublicA = stackalloc byte[Srp6Calculator.EphemeralKeyLength];
        Span<byte> clientProofM1 = stackalloc byte[Srp6Calculator.ProofLength];

        if (!AuthPayloadParser.TryParseClientProof(payload, clientPublicA, clientProofM1))
        {
            _logger.LogWarning(
                "Malformed CMSG_BATTLENET_CHALLENGE_RESPONSE packet. ConnectionId={ConnectionId}, PayloadBytes={PayloadBytes}. Disconnecting.",
                context.ConnectionId,
                payload.Length);
            return AuthDispatchResult.Disconnect;
        }

        if (!_sessionManager.TryGet(context.ConnectionId, out AuthSession? session))
        {
            _logger.LogWarning(
                "SRP6 proof received without active auth session. ConnectionId={ConnectionId}. Disconnecting.",
                context.ConnectionId);
            return AuthDispatchResult.Disconnect;
        }

        if (!session.TryTransitionToProof(clientPublicA, clientProofM1) ||
            !session.TryCaptureSrpMaterial(out AuthSessionSrpMaterial material))
        {
            _logger.LogWarning(
                "Auth session state is invalid for proof stage. ConnectionId={ConnectionId}. Disconnecting.",
                context.ConnectionId);
            return AuthDispatchResult.Disconnect;
        }

        bool valid = _srp6.TryVerifyClientProof(
            material.Username,
            material.Salt,
            material.Verifier,
            material.ServerPrivateb,
            material.ServerPublicB,
            clientPublicA,
            clientProofM1,
            out Srp6ProofResult proofResult);

        CryptographicOperations.ZeroMemory(material.Salt);
        CryptographicOperations.ZeroMemory(material.Verifier);
        CryptographicOperations.ZeroMemory(material.ServerPrivateb);
        CryptographicOperations.ZeroMemory(material.ServerPublicB);

        if (!valid)
        {
            _sessionManager.Remove(context.ConnectionId);

            await context.SendPacketAsync(
                Retail1201AuthOpcodes.SmsgAuthResponse,
                AuthPayloadFactory.CreateFailure(BridgeAuthStatus.InvalidProof),
                cancellationToken).ConfigureAwait(false);

            _logger.LogWarning(
                "Invalid SRP6 proof for '{Username}'. ConnectionId={ConnectionId}. Disconnecting.",
                material.Username,
                context.ConnectionId);

            return AuthDispatchResult.Disconnect;
        }

        bool updated = await _databaseService
            .UpdateSessionKey(material.AccountId, proofResult.SessionKey, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        if (!updated)
        {
            CryptographicOperations.ZeroMemory(proofResult.SessionKey);
            CryptographicOperations.ZeroMemory(proofResult.ServerProofM2);

            await context.SendPacketAsync(
                Retail1201AuthOpcodes.SmsgAuthResponse,
                AuthPayloadFactory.CreateFailure(BridgeAuthStatus.InternalError),
                cancellationToken).ConfigureAwait(false);

            return AuthDispatchResult.Disconnect;
        }

        session.MarkAuthenticated(proofResult.SessionKey);

        byte[] responsePayload = AuthPayloadFactory.CreateProofSuccess(proofResult.ServerProofM2);
        await context.SendPacketAsync(
            Retail1201AuthOpcodes.SmsgAuthResponse,
            responsePayload,
            cancellationToken).ConfigureAwait(false);

        CryptographicOperations.ZeroMemory(proofResult.ServerProofM2);

        _logger.LogInformation(
            "SRP6 authentication success for '{Username}'. ConnectionId={ConnectionId}",
            material.Username,
            context.ConnectionId);

        return AuthDispatchResult.Continue;
    }
}

internal readonly record struct RetailAuthSessionPacket(
    uint ProtocolVersion,
    ushort ClientBuild,
    string Architecture,
    string OperatingSystem,
    string Username);

internal static class AuthPayloadParser
{
    private const int MaxPayloadBytes = 16 * 1024;

    public static bool TryParseAuthSession(ReadOnlySequence<byte> payload, out RetailAuthSessionPacket packet)
    {
        packet = default;
        if (!TryGetPayloadSpan(payload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            return false;
        }

        try
        {
            return TryParseAuthSessionLayoutTagged(span, out packet) ||
                   TryParseAuthSessionLayoutString(span, 7, 7, 9, out packet) ||
                   TryParseAuthSessionLayoutString(span, 8, 8, 9, out packet);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public static bool TryParseClientProof(
        ReadOnlySequence<byte> payload,
        Span<byte> clientPublicA,
        Span<byte> clientProofM1)
    {
        if (!TryGetPayloadSpan(payload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            return false;
        }

        try
        {
            var reader = new PacketReader(span);
            if (reader.TryReadBytes(clientPublicA) &&
                reader.TryReadBytes(clientProofM1))
            {
                return true;
            }

            // Compatibility fallback:
            // [uint8 A_len][A][uint8 M1_len][M1]
            reader = new PacketReader(span);
            if (!reader.TryReadByte(out byte aLen) || aLen != clientPublicA.Length)
            {
                return false;
            }

            if (!reader.TryReadBytes(clientPublicA))
            {
                return false;
            }

            if (!reader.TryReadByte(out byte m1Len) || m1Len != clientProofM1.Length)
            {
                return false;
            }

            return reader.TryReadBytes(clientProofM1);
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    public static bool IsLikelyRealmListRequest(ReadOnlySequence<byte> payload)
    {
        if (payload.Length == 0)
        {
            return true;
        }

        if (!TryGetPayloadSpan(payload, out byte[]? rented, out ReadOnlySpan<byte> span))
        {
            return false;
        }

        try
        {
            var reader = new PacketReader(span);
            if (reader.TryReadUInt32LittleEndian(out uint requestCode))
            {
                return requestCode is 0 or 1 or 2 or 0x10 or 0x1000;
            }

            reader = new PacketReader(span);
            return reader.TryReadByte(out byte requestByte) && requestByte is 0 or 1 or 0x10;
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    private static bool TryParseAuthSessionLayoutTagged(
        ReadOnlySpan<byte> payload,
        out RetailAuthSessionPacket packet)
    {
        packet = default;
        var reader = new PacketReader(payload);

        if (!reader.TryReadUInt32LittleEndian(out uint protocolVersion) ||
            !reader.TryReadUInt16LittleEndian(out ushort clientBuild) ||
            !reader.TryReadUInt32LittleEndian(out uint architectureTag) ||
            !reader.TryReadUInt32LittleEndian(out uint osTag) ||
            !reader.TryReadLengthPrefixedString(9, 320, out string rawLogin))
        {
            return false;
        }

        if (!TryNormalizeUsername(rawLogin, out string username))
        {
            return false;
        }

        packet = new RetailAuthSessionPacket(
            protocolVersion,
            clientBuild,
            $"0x{architectureTag:X8}",
            $"0x{osTag:X8}",
            username);

        return true;
    }

    private static bool TryParseAuthSessionLayoutString(
        ReadOnlySpan<byte> payload,
        int architectureBits,
        int osBits,
        int loginBits,
        out RetailAuthSessionPacket packet)
    {
        packet = default;
        var reader = new PacketReader(payload);

        if (!reader.TryReadUInt32LittleEndian(out uint protocolVersion) ||
            !reader.TryReadUInt16LittleEndian(out ushort clientBuild) ||
            !reader.TryReadLengthPrefixedString(architectureBits, 16, out string architecture) ||
            !reader.TryReadLengthPrefixedString(osBits, 16, out string os) ||
            !reader.TryReadLengthPrefixedString(loginBits, 320, out string rawLogin))
        {
            return false;
        }

        if (!TryNormalizeUsername(rawLogin, out string username))
        {
            return false;
        }

        packet = new RetailAuthSessionPacket(
            protocolVersion,
            clientBuild,
            architecture.Trim(),
            os.Trim(),
            username);

        return true;
    }

    private static bool TryNormalizeUsername(string rawValue, out string username)
    {
        username = string.Empty;
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return false;
        }

        string value = rawValue.Trim().Trim('\0');
        int atIndex = value.IndexOf('@');
        if (atIndex > 0)
        {
            value = value[..atIndex];
        }

        value = value.Trim();
        if (value.Length == 0 || value.Length > 64)
        {
            return false;
        }

        username = value;
        return true;
    }

    private static bool TryGetPayloadSpan(
        ReadOnlySequence<byte> payload,
        out byte[]? rented,
        out ReadOnlySpan<byte> span)
    {
        rented = null;
        span = default;

        if (payload.Length <= 0 || payload.Length > MaxPayloadBytes)
        {
            return false;
        }

        if (payload.IsSingleSegment)
        {
            span = payload.FirstSpan;
            return true;
        }

        int length = (int)payload.Length;
        rented = ArrayPool<byte>.Shared.Rent(length);
        Span<byte> destination = rented.AsSpan(0, length);
        payload.CopyTo(destination);
        span = destination;
        return true;
    }
}

internal static class AuthPayloadFactory
{
    public static bool TryCreateSrp6Challenge(
        ReadOnlySpan<byte> publicB,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> generator,
        ReadOnlySpan<byte> modulus,
        out byte[] payload)
    {
        payload = Array.Empty<byte>();
        if (publicB.Length != Srp6Calculator.EphemeralKeyLength ||
            salt.Length != Srp6Calculator.SaltLength ||
            generator.Length != 1 ||
            modulus.Length != Srp6Calculator.EphemeralKeyLength)
        {
            return false;
        }

        payload = new byte[publicB.Length + salt.Length + generator.Length + modulus.Length];
        int offset = 0;

        publicB.CopyTo(payload.AsSpan(offset));
        offset += publicB.Length;
        salt.CopyTo(payload.AsSpan(offset));
        offset += salt.Length;
        generator.CopyTo(payload.AsSpan(offset));
        offset += generator.Length;
        modulus.CopyTo(payload.AsSpan(offset));

        return true;
    }

    public static byte[] CreateProofSuccess(ReadOnlySpan<byte> serverM2)
    {
        byte[] payload = new byte[1 + serverM2.Length];
        payload[0] = (byte)BridgeAuthStatus.Success;
        serverM2.CopyTo(payload.AsSpan(1));
        return payload;
    }

    public static byte[] CreateFailure(BridgeAuthStatus status)
    {
        return new[] { (byte)status };
    }
}
