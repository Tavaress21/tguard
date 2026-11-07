using TGuard.Core;
using TGuard.Core.Storage;
using TGuard.Service;

TGuardPaths.Ensure();

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "TGuard");
builder.Logging.AddEventLog(o => o.SourceName = "TGuard");

builder.Services.AddSingleton<ServiceState>();
builder.Services.AddSingleton<Notifier>();
builder.Services.AddSingleton<ScanManager>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<Notifier>());
builder.Services.AddSingleton<RealtimeProtection>();
builder.Services.AddSingleton<ProcessGuard>();
builder.Services.AddSingleton<UsbGuard>();
builder.Services.AddSingleton<UpdateService>();
builder.Services.AddSingleton<RansomwareGuard>();
builder.Services.AddSingleton<EmailGuard>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<RealtimeProtection>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<ProcessGuard>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<UsbGuard>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<UpdateService>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<RansomwareGuard>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<EmailGuard>());
builder.Services.AddSingleton<SiteSync>();
builder.Services.AddSingleton<SupportChat>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SiteSync>());
builder.Services.AddHostedService<PipeServer>();
builder.Services.AddHostedService<Scheduler>();

var host = builder.Build();
Loc.Language = host.Services.GetRequiredService<ServiceState>().Settings.Language;
host.Run();
