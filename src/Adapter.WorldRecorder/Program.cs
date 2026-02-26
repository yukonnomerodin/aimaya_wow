using Adapter.WorldRecorder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.IO;

var builder = Host.CreateApplicationBuilder(args);
string appBasePath = AppContext.BaseDirectory;

builder.Configuration
    .AddJsonFile(Path.Combine(appBasePath, "appsettings.json"), optional: true, reloadOnChange: true)
    .AddJsonFile(Path.Combine(appBasePath, $"appsettings.{builder.Environment.EnvironmentName}.json"), optional: true, reloadOnChange: true)
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables(prefix: "WORLDREC_")
    .AddCommandLine(args);

builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff zzz ";
});

builder.Services
    .AddOptions<WorldRecorderOptions>()
    .Bind(builder.Configuration.GetSection(WorldRecorderOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddHostedService<WorldRecorderListener>();

using IHost host = builder.Build();
await host.RunAsync();
