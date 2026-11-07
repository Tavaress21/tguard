using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TGuard.Core.Ipc;
using TGuard.Core.Online;
using TGuard.Core.Security;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class PipeServer : BackgroundService
{
    private readonly ServiceState _state;
    private readonly ScanManager _scans;
    private readonly ILogger<PipeServer> _log;
    private readonly RealtimeProtection _realtime;
    private readonly ProcessGuard _processGuard;
    private readonly UsbGuard _usb;
    private readonly UpdateService _updates;
    private readonly RansomwareGuard _ransomware;
    private readonly EmailGuard _email;
    private readonly SiteSync _sync;

    public PipeServer(ServiceState state, ScanManager scans, ILogger<PipeServer> log,
                      RealtimeProtection realtime, ProcessGuard processGuard, UsbGuard usb, UpdateService updates,
                      RansomwareGuard ransomware, EmailGuard email, SiteSync sync)
    {
        _sync = sync;
        _ransomware = ransomware;
        _email = email;
        _state = state;
        _scans = scans;
        _log = log;
        _realtime = realtime;
        _processGuard = processGuard;
        _usb = usb;
        _updates = updates;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = PipeFactory.Create(Protocol.PipeName, PipeDirection.InOut);
                await pipe.WaitForConnectionAsync(ct);
                var connected = pipe;
                pipe = null;
                _ = Task.Run(() => Serve(connected, ct), ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _log.LogWarning(ex, "Pipe error"); await Task.Delay(500, ct); }
            finally { if (pipe is not null) await pipe.DisposeAsync(); }
        }
    }

    private async Task Serve(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
                var line = await reader.ReadLineAsync(ct);
                if (line is null) return;
                Response resp;
                try
                {
                    var req = JsonSerializer.Deserialize<Request>(line, Protocol.Json) ?? new Request();
                    var privileged = Privileged.Contains(req.Cmd)
                        || (req.Cmd == "scan.start" && req.Args?["type"]?.GetValue<string>() == "custom");
                    if (privileged && !ClientVerifier.IsTrustedClient(pipe, out var who))
                    {
                        _log.LogWarning("Rejected '{Cmd}' from untrusted client ({Who})", req.Cmd, who);
                        resp = Response.Fail("ACCESS_DENIED: only the installed TGuard app can change protection settings.");
                    }
                    else resp = await Handle(req);
                }
                catch (Exception ex) { resp = Response.Fail(ex.Message); }
                await writer.WriteLineAsync(JsonSerializer.Serialize(resp, Protocol.Json));
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
        }
    }

    private static readonly HashSet<string> Privileged = new()
        { "settings.set", "quarantine.restore", "quarantine.delete", "scan.cancel", "trust.remove",
          "account.link.start", "account.link.poll", "account.unlink", "report.send", "email.add", "email.remove",
          "update.install", "update.snooze" };

    private AccountStatus Account() => new()
    {
        Linked = !string.IsNullOrEmpty(_state.State.AccountToken),
        Name = _state.State.AccountName,
        Email = _state.State.AccountEmail,
        UsageStats = _state.Settings.UsageStats,
        RemoteControl = _state.Settings.RemoteControl,
    };

    private async Task<Response> Handle(Request req)
    {
        string Arg(string n) => req.Args?[n]?.GetValue<string>() ?? "";
        switch (req.Cmd)
        {
            case "status":
                return Response.Success(new ServiceStatus
                {
                    Version = typeof(PipeServer).Assembly.GetName().Version?.ToString(3) ?? "",
                    RealtimeEnabled = _state.Settings.RealtimeEnabled,
                    ProcessGuardActive = _processGuard.Active,
                    UsbProtection = _usb.Active,
                    RansomwareActive = _ransomware.Active,
                    ProtectedFolders = _ransomware.ProtectedFolderCount,
                    EmailActive = _email.Active,
                    EmailAccounts = _email.Accounts().Count,
                    AccountLinked = !string.IsNullOrEmpty(_state.State.AccountToken),
                    AutoUpdate = _state.Settings.AutoUpdate,
                    BadUrls = _state.Engine.Blocklist.Count,
                    LastUpdate = _state.State.LastUpdate,
                    WatchedFolders = _realtime.WatchedFolders,
                    Signatures = _state.Engine.Signatures.Count,
                    Rules = _state.Engine.Rules.Rules.Count,
                    QuarantineCount = _state.Quarantine.List().Count,
                    ThreatsLast30Days = _state.Events.ThreatsSince(DateTimeOffset.Now.AddDays(-30)),
                    LastScan = _state.State.LastScan,
                    CurrentScan = _scans.Current,
                });

            case "scan.start":
                var paths = req.Args?["paths"] is JsonArray arr ? arr.Select(n => n!.GetValue<string>()).ToList() : null;
                return Response.Success(_scans.Start(Arg("type") is { Length: > 0 } t ? t : "quick", paths));
            case "scan.cancel":
                _scans.Cancel();
                return Response.Success();
            case "scan.progress":
                return Response.Success(_scans.Current);

            case "quarantine.list":
                return Response.Success(_state.Quarantine.List());
            case "quarantine.restore":
            {
                var item = _state.Quarantine.List().FirstOrDefault(i => i.Id == Arg("id"))
                           ?? throw new KeyNotFoundException("Quarantine item not found");
                _state.Engine.Trust.Add(item.Sha256, item.OriginalPath);
                return Response.Success(new { path = _state.Quarantine.Restore(item.Id) });
            }
            case "quarantine.delete":
                _state.Quarantine.Delete(Arg("id"));
                return Response.Success();

            case "update.now":
                return Response.Success(await _updates.RunAsync());
            case "update.pending":
                return Response.Success(_updates.Pending);
            case "update.install":
                return (await _updates.InstallPendingAsync())
                    ? Response.Success()
                    : Response.Fail("no update is waiting to be installed");
            case "update.snooze":
                return Response.Success(_updates.Snooze(TimeSpan.FromHours(req.Args?["hours"]?.GetValue<int>() is int h and > 0 and <= 168 ? h : 24)));

            case "trust.list":
                return Response.Success(_state.Engine.Trust.List());
            case "trust.remove":
                _state.Engine.Trust.Remove(Arg("sha256"));
                return Response.Success();

            case "events":
                return Response.Success(_state.Events.Recent(300, onlyThreats: req.Args?["onlyThreats"]?.GetValue<bool>() ?? true));

            case "check":
                return Response.Success(await Task.Run(SecurityCheck.Run));

            case "settings.get":
                return Response.Success(_state.Settings);
            case "settings.set":
                var s = req.Args?.Deserialize<TGuardSettings>(Protocol.Json);
                if (s is null) return Response.Fail("invalid settings");
                s.UpdateUrl = _state.Settings.UpdateUrl;
                s.ExtraUpdateKeys = _state.Settings.ExtraUpdateKeys;
                s.SiteUrl = _state.Settings.SiteUrl;
                _state.UpdateSettings(s);
                return Response.Success(s);

            case "email.list":
                return Response.Success(_email.Accounts());
            case "email.add":
                return Response.Success(await _email.AddAsync(Arg("user"), Arg("password"), Arg("host"),
                    req.Args?["port"]?.GetValue<int>() ?? 0, req.Args?["ssl"]?.GetValue<bool>() ?? true,
                    req.Args?["moveThreats"]?.GetValue<bool>() ?? true, CancellationToken.None));
            case "email.remove":
                _email.Remove(Arg("id"));
                return Response.Success(_email.Accounts());
            case "email.check":
                _email.CheckNow();
                return Response.Success();

            case "account.status":
                return Response.Success(Account());
            case "account.link.start":
                return Response.Success(await new SiteClient(_state.Settings).StartLinkAsync(_state.State.EnsureInstallId()));
            case "account.link.poll":
            {
                var poll = await new SiteClient(_state.Settings).PollLinkAsync(Arg("secret"));
                if (poll.Linked && !string.IsNullOrEmpty(poll.Token))
                {
                    _state.State.AccountToken = poll.Token;
                    _state.State.AccountName = poll.Account?.Name;
                    _state.State.AccountEmail = poll.Account?.Email;
                    _state.State.LastPing = null;
                    _state.State.Save();
                    _sync.SyncSoon();
                }
                return Response.Success(new { poll.Linked, poll.Expired, account = Account() });
            }
            case "account.unlink":
            {
                var token = _state.State.AccountToken;
                _state.State.AccountToken = null;
                _state.State.AccountName = null;
                _state.State.AccountEmail = null;
                _state.State.Save();
                if (!string.IsNullOrEmpty(token))
                {
                    try { await new SiteClient(_state.Settings).UnlinkAsync(token); }
                    catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { _log.LogInformation("Unlink: {Error}", ex.Message); }
                }
                return Response.Success(Account());
            }
            case "report.send":
            {
                var report = req.Args?.Deserialize<ReportRequest>(Protocol.Json) ?? throw new ArgumentException("invalid report");
                if (report.Type is not ("scam" or "malware" or "false_positive" or "other")) throw new ArgumentException("invalid report type");
                var id = await new SiteClient(_state.Settings).ReportAsync(_state.State.EnsureInstallId(), _state.State.AccountToken, report);
                return Response.Success(new { id });
            }

            default:
                return Response.Fail($"unknown command: {req.Cmd}");
        }
    }
}
