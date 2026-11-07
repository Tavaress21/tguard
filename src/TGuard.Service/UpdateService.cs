using System.Diagnostics;
using System.Text.Json;
using TGuard.Core;
using TGuard.Core.Ipc;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class UpdateService : ResilientService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(3);

    private readonly ServiceState _state;
    private readonly Notifier _notifier;
    private readonly ILogger<UpdateService> _log;
    private readonly Updater _updater = new();
    private readonly AppUpdater _appUpdater = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UpdateService(ServiceState state, Notifier notifier, ILogger<UpdateService> log)
        : base(log)
    {
        _state = state;
        _notifier = notifier;
        _log = log;
    }

    protected override async Task LoopAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(2), ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            var st = _state.State;
            var due = st.LastUpdate is null || DateTimeOffset.Now - st.LastUpdate > Interval;
            var backoff = st.LastUpdateAttempt is not null && DateTimeOffset.Now - st.LastUpdateAttempt < TimeSpan.FromHours(1);
            if (_state.Settings.AutoUpdate && due && !backoff)
                await RunAsync(installAppUpdate: _state.Settings.AutoInstallUpdates, ct);
            try { await Task.Delay(TimeSpan.FromMinutes(15), ct); } catch (OperationCanceledException) { return; }
        }
    }

    public async Task<UpdateReport> RunAsync(bool installAppUpdate = true, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var report = await _updater.RunAsync(_state.Engine, _state.Settings, ct);
            _state.State.LastUpdateAttempt = DateTimeOffset.Now;
            if (report.Success) _state.State.LastUpdate = DateTimeOffset.Now;
            _state.State.Save();
            _log.LogInformation("Update: sources={Sources} signatures+={Sigs} urls+={Urls} errors={Errors}",
                string.Join(",", report.Sources), report.SignaturesAdded, report.UrlsAdded, string.Join(" | ", report.Errors));

            if (installAppUpdate && !string.IsNullOrWhiteSpace(_state.Settings.UpdateUrl))
                await CheckAppUpdateAsync(report, ct);
            return report;
        }
        finally { _gate.Release(); }
    }

    private async Task CheckAppUpdateAsync(UpdateReport report, CancellationToken ct)
    {
        try
        {
            var release = await _appUpdater.CheckAsync(_state.Settings, ct);
            if (release is null) return;
            _log.LogInformation("New TGuard version {Version} available, downloading", release.Version);
            var folder = Path.Combine(TGuardPaths.Root, "Updates");
            if (Directory.Exists(folder)) foreach (var old in Directory.GetFiles(folder)) File.Delete(old);
            var installer = await _appUpdater.DownloadAsync(_state.Settings, release, folder, ct);
            report.Notes.Add($"app: installing {release.Version}");

            _notifier.Publish(new Notification
            {
                Kind = "app-update",
                Title = Loc.Pick("A atualizar o TGuard", "Updating TGuard"),
                Message = Loc.Pick($"A instalar a versão {release.Version}…", $"Installing version {release.Version}..."),
            });
            await Task.Delay(TimeSpan.FromSeconds(3), ct);

            Process.Start(new ProcessStartInfo(installer,
                $"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=\"{Path.Combine(TGuardPaths.Logs, "update.log")}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException or UriFormatException or IOException or System.ComponentModel.Win32Exception)
        {
            report.Errors.Add($"app update: {ex.Message}");
            _log.LogWarning("App update check failed: {Error}", ex.Message);
        }
    }
}
