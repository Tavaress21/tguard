using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;

namespace TGuard.Service;

/// <summary>
/// Scans USB and other removable drives as soon as they are plugged in and keeps them under
/// real-time watch until they are removed.
/// </summary>
public sealed class UsbGuard : BackgroundService
{
    private const int MaxFilesPerDrive = 50_000;

    private readonly ServiceState _state;
    private readonly RealtimeProtection _realtime;
    private readonly Notifier _notifier;
    private readonly ILogger<UsbGuard> _log;
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);

    public UsbGuard(ServiceState state, RealtimeProtection realtime, Notifier notifier, ILogger<UsbGuard> log)
    {
        _state = state;
        _realtime = realtime;
        _notifier = notifier;
        _log = log;
    }

    public bool Active => _state.Settings.UsbScanEnabled;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // drives already plugged in at boot are watched but not scanned again
        foreach (var d in RemovableDrives()) { _known.Add(d); _realtime.AddDrive(d); }

        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(3000, ct); } catch (OperationCanceledException) { return; }
            var now = RemovableDrives().ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var gone in _known.Where(k => !now.Contains(k)).ToList())
            {
                _known.Remove(gone);
                _realtime.RemoveDrive(gone);
            }
            foreach (var added in now.Where(n => !_known.Contains(n)).ToList())
            {
                _known.Add(added);
                _realtime.AddDrive(added);
                if (_state.Settings.UsbScanEnabled) _ = Task.Run(() => ScanDrive(added, ct), ct);
            }
        }
    }

    private static IEnumerable<string> RemovableDrives()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            bool ok;
            try { ok = d.DriveType == DriveType.Removable && d.IsReady; } catch (IOException) { ok = false; }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    private void ScanDrive(string root, CancellationToken ct)
    {
        _log.LogInformation("Removable drive {Drive} connected, scanning", root);
        _notifier.Publish(new Notification
        {
            Kind = "usb", Title = Loc.Pick("Pen USB ligada", "USB drive connected"),
            Message = Loc.Pick($"A analisar {root}…", $"Scanning {root}..."),
        });
        int files = 0, threats = 0;
        try
        {
            foreach (var f in _state.Engine.EnumerateFiles(root, ct))
            {
                if (++files > MaxFilesPerDrive || !Directory.Exists(root)) break;
                var r = _state.Engine.ScanFile(f, ct: ct);
                if (_state.Handle(r, "usb") is not null) threats++;
            }
        }
        catch (OperationCanceledException) { return; }
        catch (Exception ex) { _log.LogWarning(ex, "USB scan of {Drive} failed", root); }

        _log.LogInformation("USB scan of {Drive}: {Files} files, {Threats} threats", root, files, threats);
        _notifier.Publish(new Notification
        {
            Kind = "usb-done",
            Title = threats == 0 ? Loc.Pick("Pen USB segura", "USB drive is clean") : Loc.Pick("Ameaças na pen USB", "Threats on USB drive"),
            Message = Loc.Pick($"{root}: {files} ficheiros analisados, {threats} ameaça(s).", $"{root}: {files} files scanned, {threats} threat(s)."),
        });
    }
}
