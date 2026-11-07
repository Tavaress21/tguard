using System.Text.Json;
using TGuard.Core;
using TGuard.Core.Ipc;
using TGuard.Core.Online;
using TGuard.Core.Security;
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
    private readonly Notifier _notifier;
    private readonly ILogger<SiteSync> _log;
    private readonly List<CommandResult> _results = new();
    private readonly SemaphoreSlim _wake = new(0);
    private DateTimeOffset _lastAttempt = DateTimeOffset.MinValue;

    public SiteSync(ServiceState state, ScanManager scans, UpdateService updates, RealtimeProtection realtime, ProcessGuard processGuard,
                    UsbGuard usb, RansomwareGuard ransomware, EmailGuard email, Notifier notifier, ILogger<SiteSync> log)
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
        _notifier = notifier;
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
            Status = Status(linked),
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
            if (response.AccountRevoked) _state.ForgetAccount();
            else
            {
                if (response.AccountName is not null) st.AccountName = response.AccountName;
                st.Save();
            }
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
            result = _state.Settings.RemoteControl
                ? await ExecuteAsync(command, ct)
                : Done(command, false, Loc.Pick("As ações remotas estão desligadas neste PC. Liga-as no TGuard, em Definições > Conta.",
                                                "Remote actions are turned off on this PC. Turn them on in TGuard, Settings > Account."));
        }
        catch (Exception ex)
        {
            result = Done(command, false, ex.Message);
        }
        _log.LogInformation("Remote command {Type} ({Id}): {Message}", command.Type, command.Id, result.Message);
        if (_state.Settings.RemoteControl)
            _notifier.Publish(new Notification
            {
                Kind = "remote",
                Title = Loc.Pick("Pedido da área de cliente", "Request from the client area"),
                Message = result.Message,
            });
        lock (_results) _results.Add(result);
        _wake.Release();
    }

    private async Task<CommandResult> ExecuteAsync(RemoteCommand command, CancellationToken ct)
    {
        string Arg(string name) => command.Args.TryGetValue(name, out var v) ? v : "";

        switch (command.Type)
        {
            case "scan.quick":
            case "scan.full":
            {
                var type = command.Type == "scan.full" ? "full" : "quick";
                if (_scans.Running) return Done(command, false, Loc.Pick("Já está a decorrer uma análise.", "A scan is already running."));
                _scans.Start(type);
                return Done(command, true, type == "full" ? Loc.Pick("Análise completa iniciada.", "Full scan started.") : Loc.Pick("Análise rápida iniciada.", "Quick scan started."));
            }
            case "scan.cancel":
                if (!_scans.Running) return Done(command, false, Loc.Pick("Não há nenhuma análise a decorrer.", "No scan is running."));
                _scans.Cancel();
                return Done(command, true, Loc.Pick("Análise cancelada.", "Scan cancelled."));
            case "update":
            {
                var report = await _updates.RunAsync(installAppUpdate: false, ct);
                var pending = _updates.Pending;
                var message = report.Success
                    ? Loc.Pick($"Atualizado: +{report.SignaturesAdded} assinaturas, +{report.UrlsAdded} sites.", $"Updated: +{report.SignaturesAdded} signatures, +{report.UrlsAdded} sites.")
                    : string.Join(" | ", report.Errors);
                if (pending is not null)
                    message += Loc.Pick($" A versão {pending.Version} está pronta: confirma no PC para instalar.", $" Version {pending.Version} is ready: confirm on the PC to install it.");
                return Done(command, report.Success, message);
            }
            case "email.check":
                if (_email.Accounts().Count == 0) return Done(command, false, Loc.Pick("Não há contas de email neste PC.", "There are no email accounts on this PC."));
                _email.CheckNow();
                return Done(command, true, Loc.Pick("Verificação do email iniciada.", "Email check started."));
            case "protection.set":
            {
                var enabled = Arg("enabled") is "true" or "1";
                var settings = JsonSerializer.Deserialize<TGuardSettings>(JsonSerializer.Serialize(_state.Settings))!;
                var name = Arg("module") switch
                {
                    "realtime" => Set(() => settings.RealtimeEnabled = enabled, Loc.Pick("Proteção em tempo real", "Real-time protection")),
                    "process_guard" => Set(() => settings.ProcessGuardEnabled = enabled, Loc.Pick("Bloqueio de programas", "Execution blocking")),
                    "usb" => Set(() => settings.UsbScanEnabled = enabled, Loc.Pick("Pens USB", "USB drives")),
                    "ransomware" => Set(() => settings.RansomwareProtection = enabled, Loc.Pick("Anti-ransomware", "Anti-ransomware")),
                    "email" => Set(() => settings.EmailProtection = enabled, Loc.Pick("Proteção de email", "Email protection")),
                    _ => null,
                };
                if (name is null) return Done(command, false, "unknown module");
                _state.UpdateSettings(settings);
                return Done(command, true, enabled ? Loc.Pick($"{name} ligada.", $"{name} turned on.") : Loc.Pick($"{name} desligada.", $"{name} turned off."));
            }
            case "quarantine.restore":
            {
                var item = _state.Quarantine.List().FirstOrDefault(i => i.Id == Arg("id"));
                if (item is null) return Done(command, false, Loc.Pick("Este ficheiro já não está na quarentena.", "This file is no longer in quarantine."));
                _state.Engine.Trust.Add(item.Sha256, item.OriginalPath);
                _state.Quarantine.Restore(item.Id);
                return Done(command, true, Loc.Pick($"{Path.GetFileName(item.OriginalPath)} foi restaurado.", $"{Path.GetFileName(item.OriginalPath)} was restored."));
            }
            case "quarantine.delete":
            {
                var item = _state.Quarantine.List().FirstOrDefault(i => i.Id == Arg("id"));
                if (item is null) return Done(command, false, Loc.Pick("Este ficheiro já não está na quarentena.", "This file is no longer in quarantine."));
                _state.Quarantine.Delete(item.Id);
                return Done(command, true, Loc.Pick($"{Path.GetFileName(item.OriginalPath)} foi apagado.", $"{Path.GetFileName(item.OriginalPath)} was deleted."));
            }
            case "check":
                _security = null;
                return Done(command, true, Loc.Pick("Verificação do PC atualizada.", "PC check refreshed."));
            default:
                return Done(command, false, "unknown command");
        }

        static string? Set(Action apply, string label)
        {
            apply();
            return label;
        }
    }

    private static CommandResult Done(RemoteCommand c, bool ok, string message) => new() { Id = c.Id, Ok = ok, Message = Trim(message, 500) ?? "" };

    private List<RemoteCheck>? _security;
    private DateTimeOffset? _securityAt;

    private List<RemoteCheck> Security()
    {
        if (_security is not null && _securityAt is not null && DateTimeOffset.Now - _securityAt < TimeSpan.FromHours(6)) return _security;
        _security = SecurityCheck.Run().Select(c => new RemoteCheck
        {
            Id = c.Id,
            Title = Trim(c.Title, 80) ?? "",
            Status = c.Status.ToString().ToLowerInvariant(),
            Detail = Trim(c.Detail, 200) ?? "",
        }).Take(30).ToList();
        _securityAt = DateTimeOffset.Now;
        return _security;
    }

    private DeviceStatus Status(bool linked)
    {
        var scan = _scans.Current;
        var status = new DeviceStatus
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
            ScanType = scan?.Running == true ? scan.Type : null,
            ScanThreats = scan?.Running == true ? scan.Threats : 0,
            ScanStarted = scan?.Running == true ? scan.Started : null,
            RemoteControl = linked && _state.Settings.RemoteControl,
            PendingUpdate = _updates.Pending?.Version,
        };
        if (!linked) return status;

        status.QuarantineItems = _state.Quarantine.List().OrderByDescending(i => i.Date).Take(50).Select(i => new RemoteQuarantineItem
        {
            Id = i.Id,
            Name = Trim(Path.GetFileName(i.OriginalPath), 200) ?? "",
            Threat = Trim(i.Threat, 120) ?? "",
            Date = i.Date,
            Size = i.Size,
        }).ToList();
        status.EmailList = _email.Accounts().Take(10).Select(a => new RemoteEmailAccount
        {
            Id = a.Id,
            User = Trim(a.User, 120) ?? "",
            LastCheck = a.LastCheck,
            Ok = string.IsNullOrEmpty(a.LastError),
            Scanned = a.Scanned,
            Threats = a.Threats,
        }).ToList();
        try
        {
            status.Security = Security();
            status.SecurityAt = _securityAt;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _log.LogInformation("Security check for the site failed: {Error}", ex.Message);
        }
        return status;
    }

    private static string DisplayName(SecurityEvent e) =>
        e.Source is "email" or "process" ? e.Target : Path.GetFileName(e.Target) is { Length: > 0 } n ? n : e.Target;

    private static string? Trim(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}
