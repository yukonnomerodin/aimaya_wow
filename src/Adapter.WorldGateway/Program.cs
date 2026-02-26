using Adapter.WorldGateway;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.IO;

var builder = Host.CreateApplicationBuilder(args);
string appBasePath = AppContext.BaseDirectory;
builder.Environment.ContentRootPath = appBasePath;

builder.Configuration
    .AddJsonFile(Path.Combine(appBasePath, "appsettings.json"), optional: true, reloadOnChange: true)
    .AddJsonFile(Path.Combine(appBasePath, $"appsettings.{builder.Environment.EnvironmentName}.json"), optional: true, reloadOnChange: true)
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables(prefix: "WORLDGW_")
    .AddCommandLine(args);

builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff zzz ";
});

bool enableFileLogging = builder.Configuration.GetValue("WorldProxy:EnableFileLogging", true);
if (enableFileLogging)
{
    string configuredPath = builder.Configuration.GetValue<string>("WorldProxy:LogFilePath") ?? "docs/handshake/runlogs/worldgateway.log.txt";
    bool clearOnStart = builder.Configuration.GetValue("WorldProxy:ClearLogFileOnStart", false);

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
            Console.Error.WriteLine($"[WorldGateway][LOG] Could not clear log file '{logFilePath}': {ex.Message}. Continuing without truncation.");
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
            $"worldgateway.{DateTimeOffset.Now:yyyyMMdd_HHmmss}.log.txt");

        Console.Error.WriteLine(
            $"[WorldGateway][LOG] Could not open log file '{logFilePath}': {ex.Message}. Falling back to '{fallbackPath}'.");

        builder.Logging.AddProvider(new PlainTextFileLoggerProvider(fallbackPath));
    }
}

builder.Services
    .AddOptions<WorldProxyOptions>()
    .Bind(builder.Configuration.GetSection(WorldProxyOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<ProtocolEngineeringOptions>()
    .Bind(builder.Configuration.GetSection(ProtocolEngineeringOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddHostedService<WorldProxyListener>();

using IHost host = builder.Build();
await host.RunAsync();
