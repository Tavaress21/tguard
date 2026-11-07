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
        ClearInstalledUpdate();
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

    public PendingUpdate? Pending
    {
        get
        {
            var pending = _state.State.PendingUpdate;
            return pending is not null && IsNewer(pending.Version) && File.Exists(pending.Installer) ? pending : null;
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

            if (!string.IsNullOrWhiteSpace(_state.Settings.UpdateUrl))
                await CheckAppUpdateAsync(report, installAppUpdate, ct);
            return report;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> InstallPendingAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var pending = Pending;
            if (pending is null) return false;
            await InstallAsync(pending.Installer, pending.Version, ct);
            return true;
        }
        finally { _gate.Release(); }
    }

    public PendingUpdate? Snooze(TimeSpan duration)
    {
        var pending = Pending;
        if (pending is null) return null;
        pending.SnoozedUntil = DateTimeOffset.Now + duration;
        _state.State.Save();
        return pending;
    }

    private async Task CheckAppUpdateAsync(UpdateReport report, bool install, CancellationToken ct)
    {
        try
        {
            var release = await _appUpdater.CheckAsync(_state.Settings, ct);
            if (release is null)
            {
                ClearInstalledUpdate();
                return;
            }

            var folder = Path.Combine(TGuardPaths.Root, "Updates");
            var known = Pending is { } p && p.Version == release.Version ? p : null;
            string installer;
            if (known is not null) installer = known.Installer;
            else
            {
                _log.LogInformation("New TGuard version {Version} available, downloading", release.Version);
                if (Directory.Exists(folder)) foreach (var old in Directory.GetFiles(folder)) File.Delete(old);
                installer = await _appUpdater.DownloadAsync(_state.Settings, release, folder, ct);
            }

            if (install)
            {
                report.Notes.Add($"app: installing {release.Version}");
                await InstallAsync(installer, release.Version, ct);
                return;
            }

            if (known is not null) return;
            _state.State.PendingUpdate = new PendingUpdate
            {
                Version = release.Version,
                Installer = installer,
                Notes = release.Notes,
                Found = DateTimeOffset.Now,
            };
            _state.State.Save();
            report.Notes.Add($"app: {release.Version} ready to install");
            _notifier.Publish(new Notification
            {
                Kind = "app-update-available",
                Title = Loc.Pick("Nova versão do TGuard", "New TGuard version"),
                Message = Loc.Pick($"A versão {release.Version} está pronta a instalar. Abre o TGuard para atualizar.",
                                   $"Version {release.Version} is ready to install. Open TGuard to update."),
            });
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException or UriFormatException or IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            report.Errors.Add($"app update: {ex.Message}");
            _log.LogWarning("App update check failed: {Error}", ex.Message);
        }
    }

    private async Task InstallAsync(string installer, string version, CancellationToken ct)
    {
        _notifier.Publish(new Notification
        {
            Kind = "app-update",
            Title = Loc.Pick("A atualizar o TGuard", "Updating TGuard"),
            Message = Loc.Pick($"A instalar a versão {version}…", $"Installing version {version}..."),
        });
        await Task.Delay(TimeSpan.FromSeconds(3), ct);

        Process.Start(new ProcessStartInfo(installer,
            $"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=\"{Path.Combine(TGuardPaths.Logs, "update.log")}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });
    }

    private void ClearInstalledUpdate()
    {
        var pending = _state.State.PendingUpdate;
        if (pending is null || IsNewer(pending.Version)) return;
        _state.State.PendingUpdate = null;
        _state.State.Save();
        try { if (File.Exists(pending.Installer)) File.Delete(pending.Installer); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static bool IsNewer(string version) =>
        System.Version.TryParse(version, out var v) && v > AppUpdater.CurrentVersion;
}
