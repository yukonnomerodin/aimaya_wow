using Adapter.AuthGateway;
using Adapter.AuthGateway.Database;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MySqlConnector;
using System.Security.Cryptography.X509Certificates;

var builder = Host.CreateApplicationBuilder(args);
const string LocalAuthConnectionString = "Server=127.0.0.1;Port=3306;Database=acore_auth;User ID=yukonw;Password=skwalle;SslMode=Preferred";

builder.Configuration
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

    string certificatePath = Path.Combine(hostEnvironment.ContentRootPath, "auth.pfx");
    try
    {
        return new X509Certificate2(
            certificatePath,
            "1234",
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
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
