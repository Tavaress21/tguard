using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;
using TGuard.Core.Online;
using TGuard.Core.Security;
using TGuard.Core.Storage;

namespace TGuard.App.Services;

public sealed class Backend
{
    private readonly ServiceClient _client = new(1500);
    private readonly CancellationTokenSource _listen = new();
    private Lazy<ScanEngine> _engine = new(() => ScanEngine.CreateDefault());
    private readonly Quarantine _localQuarantine;
    private readonly EventStore _localEvents;
    private CancellationTokenSource? _localScanCts;

    private bool _serviceAvailable;

    public bool ServiceAvailable
    {
        get => _serviceAvailable || Showcase is not null;
        private set => _serviceAvailable = value;
    }

    public ServiceStatus? Showcase { get; set; }

    public bool NotificationsEnabled { get; private set; } = true;
    public ScanProgress? LocalScan { get; private set; }

    public event Action<Notification>? Notified;

    public Backend()
    {
        if (!CanWrite(TGuardPaths.Root))
            TGuardPaths.Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TGuard");
        TGuardPaths.Ensure();
        _localQuarantine = new Quarantine();
        _localEvents = new EventStore();
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, ".write-test");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch (Exception) { return false; }
    }

    private bool _listening;

    public event Action? Reconnected;

    public async Task<bool> ConnectAsync()
    {
        var was = _serviceAvailable;
        var r = await _client.SendAsync("status");
        ServiceAvailable = r.Ok;
        if (_serviceAvailable && !_listening)
        {
            _listening = true;
            _ = _client.ListenAsync(n => Notified?.Invoke(n), _listen.Token);
        }
        if (_serviceAvailable && !was) Reconnected?.Invoke();
        return _serviceAvailable;
    }

    public async Task<ServiceStatus> GetStatusAsync()
    {
        if (Showcase is not null) return Showcase;
        if (_serviceAvailable)
        {
            var r = await _client.SendAsync("status");
            if (r.Ok) return r.As<ServiceStatus>() ?? new();
            ServiceAvailable = false;
        }
        var s = TGuardSettings.Load();
        return new ServiceStatus
        {
            Version = typeof(Backend).Assembly.GetName().Version?.ToString(3) ?? "",
            RealtimeEnabled = false,
            Signatures = _engine.Value.Signatures.Count,
            Rules = _engine.Value.Rules.Rules.Count,
            QuarantineCount = _localQuarantine.List().Count,
            ThreatsLast30Days = _localEvents.Recent(1000, true).Count(e => e.Date > DateTimeOffset.Now.AddDays(-30)),
            LastScan = LocalScan?.Finished,
            CurrentScan = LocalScan,
            BadUrls = _engine.Value.Blocklist.Count,
            LastUpdate = AppState.Load().LastUpdate,
            AutoUpdate = s.AutoUpdate,
        };
    }

    public async Task<ScanProgress?> StartScanAsync(string type, List<string>? paths = null)
    {
        if (ServiceAvailable)
        {
            var r = await _client.SendAsync("scan.start", new { type, paths });
            return r.As<ScanProgress>();
        }
        if (LocalScan is { Running: true }) return LocalScan;
        var targets = type switch
        {
            "custom" => (paths ?? new()).Select(p => (p, int.MaxValue)).ToList(),
            "full" => DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable)
                               .Select(d => (d.RootDirectory.FullName, int.MaxValue)).ToList(),
            _ => new[]
            {
                (Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads", 6),
                (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), 6),
                (Path.GetTempPath(), 6),
                (Environment.GetFolderPath(Environment.SpecialFolder.Startup), 2),
                (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 1),
            }.Where(t => Directory.Exists(t.Item1)).ToList(),
        };
        _localScanCts = new CancellationTokenSource();
        var p = LocalScan = new ScanProgress { Id = Guid.NewGuid().ToString("N")[..8], Type = type, Running = true, Started = DateTimeOffset.Now };
        var ct = _localScanCts.Token;
        _ = Task.Run(() => RunLocalScan(p, targets, ct));
        return p;
    }

    private void RunLocalScan(ScanProgress p, List<(string, int)> targets, CancellationToken ct)
    {
        var engine = _engine.Value;
        var last = DateTime.MinValue;
        try
        {
            foreach (var (root, depth) in targets)
            foreach (var f in engine.EnumerateFiles(root, ct, depth))
            {
                if (f.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase)) continue;
                p.CurrentFile = f;
                var r = engine.ScanFile(f, ct: ct);
                p.FilesScanned++;
                if (r.Error is null && r.Verdict != Verdict.Clean)
                {
                    var action = "";
                    if (r.Verdict == Verdict.Malicious && engine.Settings.AutoQuarantine)
                    {
                        try { _localQuarantine.Isolate(f, r.ThreatName ?? r.Headline(), r.AllReasons()); action = Loc.Pick("Movido para a quarentena", "Moved to quarantine"); }
                        catch (Exception ex) { action = ex.Message; }
                    }
                    var t = new ThreatInfo { Path = f, Name = r.ThreatName ?? r.Headline(), Verdict = r.Verdict.ToString().ToLowerInvariant(), Score = r.Score, Reasons = r.AllReasons().ToList(), Action = action };
                    lock (p.Found) p.Found.Add(t);
                    p.Threats++;
                    _localEvents.Add(new SecurityEvent { Source = "scan", Target = f, Verdict = t.Verdict, Score = t.Score, Headline = t.Name, Reasons = t.Reasons, Action = action });
                    Notified?.Invoke(new Notification { Kind = "threat", Title = Loc.Pick("Ameaça encontrada", "Threat found"), Message = $"{Path.GetFileName(f)} — {t.Name}" });
                }
                if ((DateTime.UtcNow - last).TotalMilliseconds > 300)
                {
                    last = DateTime.UtcNow;
                    Notified?.Invoke(new Notification { Kind = "scan-progress", Data = JsonSerializer.SerializeToNode(p, Protocol.Json) });
                }
            }
        }
        catch (OperationCanceledException) { p.Cancelled = true; }
        p.Running = false;
        p.Finished = DateTimeOffset.Now;
        p.CurrentFile = "";
        Notified?.Invoke(new Notification { Kind = "scan-done", Data = JsonSerializer.SerializeToNode(p, Protocol.Json) });
    }

    public async Task CancelScanAsync()
    {
        if (ServiceAvailable) await _client.SendAsync("scan.cancel");
        else _localScanCts?.Cancel();
    }

    public async Task<List<QuarantineItem>> QuarantineAsync()
    {
        if (ServiceAvailable) return (await _client.SendAsync("quarantine.list")).As<List<QuarantineItem>>() ?? new();
        return _localQuarantine.List();
    }

    public async Task<string> RestoreAsync(string id)
    {
        if (!ServiceAvailable)
        {
            var item = _localQuarantine.List().FirstOrDefault(i => i.Id == id) ?? throw new InvalidOperationException("Quarantine item not found");
            _engine.Value.Trust.Add(item.Sha256, item.OriginalPath);
            return _localQuarantine.Restore(id);
        }
        var r = await _client.SendAsync("quarantine.restore", new { id });
        if (!r.Ok) throw new InvalidOperationException(r.Error);
        return r.Data?["path"]?.GetValue<string>() ?? "";
    }

    public async Task DeleteAsync(string id)
    {
        if (!ServiceAvailable) { _localQuarantine.Delete(id); return; }
        var r = await _client.SendAsync("quarantine.delete", new { id });
        if (!r.Ok) throw new InvalidOperationException(r.Error);
    }

    public async Task<UpdateReport> UpdateNowAsync()
    {
        if (ServiceAvailable)
        {
            var r = await new ServiceClient(300_000).SendAsync("update.now");
            if (!r.Ok) throw new InvalidOperationException(r.Error);
            return r.As<UpdateReport>() ?? new UpdateReport();
        }
        var engine = _engine.Value;
        var report = await new Updater().RunAsync(engine, engine.Settings);
        if (report.Success) { var st = AppState.Load(); st.LastUpdate = DateTimeOffset.Now; st.Save(); }
        return report;
    }

    public async Task<List<TrustedFile>> TrustedAsync()
    {
        if (ServiceAvailable) return (await _client.SendAsync("trust.list")).As<List<TrustedFile>>() ?? new();
        return _engine.Value.Trust.List();
    }

    public async Task RemoveTrustAsync(string sha256)
    {
        if (!ServiceAvailable) { _engine.Value.Trust.Remove(sha256); return; }
        var r = await _client.SendAsync("trust.remove", new { sha256 });
        if (!r.Ok) throw new InvalidOperationException(r.Error);
    }

    public async Task<List<SecurityEvent>> EventsAsync()
    {
        if (_serviceAvailable) return (await _client.SendAsync("events", new { onlyThreats = true })).As<List<SecurityEvent>>() ?? new();
        return _localEvents.Recent(300, true);
    }

    public async Task<List<CheckItem>> CheckAsync()
    {
        if (ServiceAvailable)
        {
            var r = await new ServiceClient(90_000).SendAsync("check");
            if (r.Ok) return r.As<List<CheckItem>>() ?? new();
        }
        return await Task.Run(SecurityCheck.Run);
    }

    public async Task<TGuardSettings> GetSettingsAsync()
    {
        var s = ServiceAvailable ? (await _client.SendAsync("settings.get")).As<TGuardSettings>() ?? new() : TGuardSettings.Load();
        NotificationsEnabled = s.Notifications;
        return s;
    }

    public async Task SaveSettingsAsync(TGuardSettings s)
    {
        NotificationsEnabled = s.Notifications;
        if (ServiceAvailable)
        {
            var r = await _client.SendAsync("settings.set", s);
            if (!r.Ok) throw new InvalidOperationException(r.Error);
        }
        else
        {
            s.Save();
            _engine = new Lazy<ScanEngine>(() => ScanEngine.CreateDefault(s));
        }
    }

    public async Task<AccountStatus?> AccountAsync()
    {
        if (!ServiceAvailable) return null;
        var r = await _client.SendAsync("account.status");
        return r.Ok ? r.As<AccountStatus>() : null;
    }

    public async Task<LinkStart> StartLinkAsync() =>
        (await Call("account.link.start")).As<LinkStart>() ?? throw new InvalidOperationException("no answer");

    public async Task<(bool Linked, bool Expired, AccountStatus? Account)> PollLinkAsync(string secret)
    {
        var r = await Call("account.link.poll", new { secret });
        return (r.Data?["linked"]?.GetValue<bool>() == true,
                r.Data?["expired"]?.GetValue<bool>() == true,
                r.Data?["account"]?.Deserialize<AccountStatus>(Protocol.Json));
    }

    public async Task<AccountStatus?> UnlinkAsync() => (await Call("account.unlink")).As<AccountStatus>();

    public async Task<int> ReportAsync(ReportRequest report) =>
        (await Call("report.send", report)).Data?["id"]?.GetValue<int>() ?? 0;

    private async Task<Response> Call(string cmd, object? args = null)
    {
        if (!ServiceAvailable) throw new InvalidOperationException(S.T("service.required"));
        var r = await new ServiceClient(3000).SendAsync(cmd, args);
        if (!r.Ok) throw new InvalidOperationException(r.Error);
        return r;
    }

    public void Stop() => _listen.Cancel();
}
