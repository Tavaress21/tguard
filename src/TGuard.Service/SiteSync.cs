using System.Text.Json;
using TGuard.Core;
using TGuard.Core.Online;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class SiteSync : ResilientService
{
    private static readonly TimeSpan LinkedInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan AnonymousInterval = TimeSpan.FromHours(20);

    private readonly ServiceState _state;
    private readonly ScanManager _scans;
    private readonly UpdateService _updates;
    private readonly RealtimeProtection _realtime;
    private readonly ProcessGuard _processGuard;
    private readonly UsbGuard _usb;
    private readonly RansomwareGuard _ransomware;
    private readonly EmailGuard _email;
    private readonly ILogger<SiteSync> _log;
    private readonly List<CommandResult> _results = new();
    private readonly SemaphoreSlim _wake = new(0);
    private DateTimeOffset _lastAttempt = DateTimeOffset.MinValue;

    public SiteSync(ServiceState state, ScanManager scans, UpdateService updates, RealtimeProtection realtime, ProcessGuard processGuard,
                    UsbGuard usb, RansomwareGuard ransomware, EmailGuard email, ILogger<SiteSync> log)
        : base(log)
    {
        _state = state;
        _scans = scans;
        _updates = updates;
        _realtime = realtime;
        _processGuard = processGuard;
        _usb = usb;
        _ransomware = ransomware;
        _email = email;
        _log = log;
    }

    public void SyncSoon() => _wake.Release();

    protected override async Task LoopAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(90), ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            var st = _state.State;
            var linked = !string.IsNullOrEmpty(st.AccountToken);
            var interval = linked ? LinkedInterval : AnonymousInterval;
            var wanted = linked || _state.Settings.UsageStats;
            bool pending;
            lock (_results) pending = _results.Count > 0;
            var due = st.LastPing is null || DateTimeOffset.Now - st.LastPing >= interval || (linked && pending);
            var backoff = DateTimeOffset.Now - _lastAttempt < TimeSpan.FromMinutes(2);
            if (wanted && due && !backoff) await SyncAsync(ct);
            try { await _wake.WaitAsync(TimeSpan.FromMinutes(1), ct); } catch (OperationCanceledException) { return; }
        }
    }

    private async Task SyncAsync(CancellationToken ct)
    {
        _lastAttempt = DateTimeOffset.Now;
        var st = _state.State;
        var linked = !string.IsNullOrEmpty(st.AccountToken);
        var shareEvents = linked || _state.Settings.CommunitySharing;
        var since = st.LastSyncedEvent ?? DateTimeOffset.Now.AddDays(-30);
        var events = shareEvents ? _state.Events.Since(since, 50) : new List<SecurityEvent>();

        List<CommandResult> results;
        lock (_results) results = _results.ToList();

        var request = new SyncRequest
        {
            InstallId = st.EnsureInstallId(),
            Token = st.AccountToken,
            Signatures = _state.Engine.Signatures.Count,
            Status = Status(),
            Events = events.Select(e => new SyncEvent
            {
                Date = e.Date,
                Source = e.Source,
                Verdict = e.Verdict,
                Name = Trim(e.Headline, 120),
                Score = e.Score,
                File = linked ? Trim(DisplayName(e), 200) : null,
                Action = linked ? Trim(e.Action, 200) : null,
            }).ToList(),
            Results = results,
        };

        try
        {
            var response = await new SiteClient(_state.Settings).SyncAsync(request, ct);
            st.LastPing = DateTimeOffset.Now;
            if (events.Count > 0) st.LastSyncedEvent = events.Max(e => e.Date);
            lock (_results) _results.RemoveAll(r => results.Any(x => x.Id == r.Id));
            if (response.AccountRevoked)
            {
                st.AccountToken = null;
                st.AccountName = null;
                st.AccountEmail = null;
            }
            else if (response.AccountName is not null) st.AccountName = response.AccountName;
            st.Save();
            foreach (var command in response.Commands) _ = Task.Run(() => RunAsync(command, ct), ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or UriFormatException or InvalidOperationException or IOException)
        {
            _log.LogInformation("Site sync failed: {Error}", ex.Message);
        }
    }

    private async Task RunAsync(RemoteCommand command, CancellationToken ct)
    {
        CommandResult result;
        try
        {
            switch (command.Type)
            {
                case "scan.quick":
                case "scan.full":
                    var type = command.Type == "scan.full" ? "full" : "quick";
                    if (_scans.Running) { result = Done(command, false, Loc.Pick("Já está a decorrer uma análise.", "A scan is already running.")); break; }
                    _scans.Start(type);
                    result = Done(command, true, type == "full" ? Loc.Pick("Análise completa iniciada.", "Full scan started.") : Loc.Pick("Análise rápida iniciada.", "Quick scan started."));
                    break;
                case "update":
                    var report = await _updates.RunAsync(_state.Settings.AutoInstallUpdates, ct);
                    result = Done(command, report.Success, report.Success
                        ? Loc.Pick($"Atualizado: +{report.SignaturesAdded} assinaturas, +{report.UrlsAdded} sites.", $"Updated: +{report.SignaturesAdded} signatures, +{report.UrlsAdded} sites.")
                        : string.Join(" | ", report.Errors));
                    break;
                default:
                    result = Done(command, false, "unknown command");
                    break;
            }
        }
        catch (Exception ex)
        {
            result = Done(command, false, ex.Message);
        }
        _log.LogInformation("Remote command {Type} ({Id}): {Message}", command.Type, command.Id, result.Message);
        lock (_results) _results.Add(result);
        _wake.Release();
    }

    private static CommandResult Done(RemoteCommand c, bool ok, string message) => new() { Id = c.Id, Ok = ok, Message = Trim(message, 500) ?? "" };

    private DeviceStatus Status()
    {
        var scan = _scans.Current;
        return new DeviceStatus
        {
            Realtime = _state.Settings.RealtimeEnabled && _realtime.WatchedFolders > 0,
            ProcessGuard = _processGuard.Active,
            Usb = _usb.Active,
            Ransomware = _ransomware.Active,
            Email = _state.Settings.EmailProtection,
            EmailAccounts = _email.Accounts().Count,
            Quarantine = _state.Quarantine.List().Count,
            Threats30d = _state.Events.ThreatsSince(DateTimeOffset.Now.AddDays(-30)),
            LastScan = _state.State.LastScan,
            LastScanType = _state.State.LastScanType,
            LastUpdate = _state.State.LastUpdate,
            Rules = _state.Engine.Rules.Rules.Count,
            BadUrls = _state.Engine.Blocklist.Count,
            ScanRunning = scan?.Running == true,
            ScanFiles = scan?.FilesScanned ?? 0,
        };
    }

    private static string DisplayName(SecurityEvent e) =>
        e.Source is "email" or "process" ? e.Target : Path.GetFileName(e.Target) is { Length: > 0 } n ? n : e.Target;

    private static string? Trim(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}
