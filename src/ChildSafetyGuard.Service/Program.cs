using ChildSafetyGuard.Service;
using ChildSafetyGuard.Windows;

// A Windows service starts with System32 as its working directory, so anchor configuration to the install folder.
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Services.AddWindowsService(options => options.ServiceName = GuardPaths.ServiceName);
builder.Logging.AddEventLog(settings =>
{
    settings.SourceName = GuardPaths.ServiceName; // created by scripts/Install-Service.ps1
    settings.LogName = "Application";
});

builder.Services.Configure<GuardOptions>(builder.Configuration.GetSection("Guard"));
builder.Services.AddChildSafetyGuard(GuardPaths.DefaultDataDirectory);
builder.Services.AddHostedService<EnforcementWorker>();
builder.Services.AddHostedService<BlockNoticeWorker>();

await builder.Build().RunAsync();
