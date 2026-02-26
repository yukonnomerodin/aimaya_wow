using Adapter.AuthGateway;
using Adapter.AuthGateway.Database;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MySqlConnector;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var builder = Host.CreateApplicationBuilder(args);
const string LocalAuthConnectionString = "Server=127.0.0.1;Port=3306;Database=acore_auth;User ID=aimaya;Password=aimaya;SslMode=Preferred";
string appBasePath = AppContext.BaseDirectory;
builder.Environment.ContentRootPath = appBasePath;

builder.Configuration
    .AddJsonFile(Path.Combine(appBasePath, "appsettings.json"), optional: true, reloadOnChange: true)
    .AddJsonFile(Path.Combine(appBasePath, $"appsettings.{builder.Environment.EnvironmentName}.json"), optional: true, reloadOnChange: true)
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables(prefix: "AUTHGW_")
    .AddCommandLine(args);

builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff zzz ";
});

bool enableFileLogging = builder.Configuration.GetValue("AuthListener:EnableFileLogging", true);
if (enableFileLogging)
{
    string configuredPath = builder.Configuration.GetValue<string>("AuthListener:LogFilePath")
        ?? "docs/handshake/runlogs/authgateway.log.txt";
    bool clearOnStart = builder.Configuration.GetValue("AuthListener:ClearLogFileOnStart", false);

    string logFilePath = Path.IsPathRooted(configuredPath)
        ? configuredPath
        : Path.GetFullPath(Path.Combine(appBasePath, configuredPath));

    string? logDirectory = Path.GetDirectoryName(logFilePath);
    if (!string.IsNullOrWhiteSpace(logDirectory))
    {
        Directory.CreateDirectory(logDirectory);
    }

    if (clearOnStart)
    {
        try
        {
            using var truncate = new FileStream(logFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"[AuthGateway][LOG] Could not clear log file '{logFilePath}': {ex.Message}. Continuing without truncation.");
        }
    }

    try
    {
        builder.Logging.AddProvider(new PlainTextFileLoggerProvider(logFilePath));
    }
    catch (IOException ex)
    {
        string fallbackPath = Path.Combine(
            logDirectory ?? Directory.GetCurrentDirectory(),
            $"authgateway.{DateTimeOffset.Now:yyyyMMdd_HHmmss}.log.txt");

        Console.Error.WriteLine(
            $"[AuthGateway][LOG] Could not open log file '{logFilePath}': {ex.Message}. Falling back to '{fallbackPath}'.");

        builder.Logging.AddProvider(new PlainTextFileLoggerProvider(fallbackPath));
    }
}

builder.Services
    .AddOptions<AuthListenerOptions>()
    .Bind(builder.Configuration.GetSection(AuthListenerOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<AuthSessionOptions>()
    .Bind(builder.Configuration.GetSection(AuthSessionOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<AuthOpcodeOptions>()
    .Bind(builder.Configuration.GetSection(AuthOpcodeOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddSingleton(_ =>
{
    var connectionBuilder = new MySqlConnectionStringBuilder(LocalAuthConnectionString)
    {
        Pooling = true,
        MinimumPoolSize = 16,
        MaximumPoolSize = 512,
        ConnectionTimeout = 15,
        DefaultCommandTimeout = 30
    };

    return new MySqlDataSourceBuilder(connectionBuilder.ConnectionString).Build();
});

builder.Services.AddSingleton(serviceProvider =>
{
    var hostEnvironment = serviceProvider.GetRequiredService<IHostEnvironment>();
    var logger = serviceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("AuthTls");

    // Prefer binary-local cert to keep launch topology stable across `dotnet run` vs direct exe.
    string appBaseCertPath = Path.Combine(appBasePath, "auth.pfx");
    string contentRootCertPath = Path.Combine(hostEnvironment.ContentRootPath, "auth.pfx");
    string certificatePath = File.Exists(appBaseCertPath) ? appBaseCertPath : contentRootCertPath;
    try
    {
        return new X509Certificate2(
            certificatePath,
            "1234",
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }
    catch (CryptographicException ex)
    {
        logger.LogWarning(
            ex,
            "TLS certificate load with MachineKeySet failed, retrying with CurrentUser/Ephemeral keyset. Path={Path}",
            certificatePath);

        return new X509Certificate2(
            certificatePath,
            "1234",
            X509KeyStorageFlags.UserKeySet |
            X509KeyStorageFlags.EphemeralKeySet |
            X509KeyStorageFlags.Exportable);
    }
    catch (Exception ex)
    {
        logger.LogCritical(ex, "Failed to load TLS certificate from {Path}.", certificatePath);
        throw;
    }
});

builder.Services.AddSingleton<IDatabaseService, DatabaseService>();
builder.Services.AddSingleton<IAuthOpcodeManager, AuthOpcodeManager>();
builder.Services.AddSingleton<IAuthSessionManager, AuthSessionManager>();
builder.Services.AddSingleton<ISrp6Calculator, Srp6Calculator>();

builder.Services.AddSingleton<IAuthPacketFramer>(serviceProvider =>
{
    var options = serviceProvider.GetRequiredService<IOptions<AuthListenerOptions>>().Value;
    return new BnetPacketFramer(options.MaxBnetHeaderBytes, options.MaxPacketBodyBytes);
});

builder.Services.AddSingleton<BnetConnectionHandler>();
builder.Services.AddSingleton<BnetBindHandler>();
builder.Services.AddSingleton<BnetKeepAliveHandler>();
builder.Services.AddSingleton<BnetConnectionControlHandler>();
builder.Services.AddSingleton<BnetAuthenticationLogonHandler>();
builder.Services.AddSingleton<BnetAccountHandler>();
builder.Services.AddSingleton<BnetGameUtilitiesHandler>();
builder.Services.AddSingleton<CmsgAuthSessionHandler>();
builder.Services.AddSingleton<CmsgAuthContinuedSessionHandler>();
builder.Services.AddSingleton<RealmListRequestHandler>();
builder.Services.AddSingleton<BattleNetRequestHandler>();
builder.Services.AddSingleton<BattleNetChallengeResponseHandler>();
builder.Services.AddSingleton<IAuthOpcodeDispatcher, AuthOpcodeDispatcher>();

builder.Services.AddHostedService<AuthListener>();

using var host = builder.Build();
await host.RunAsync();
