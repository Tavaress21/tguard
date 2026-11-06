using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TGuard.Core.Ipc;
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

    public PipeServer(ServiceState state, ScanManager scans, ILogger<PipeServer> log,
                      RealtimeProtection realtime, ProcessGuard processGuard, UsbGuard usb, UpdateService updates)
    {
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
                    if (Privileged.Contains(req.Cmd) && !ClientVerifier.IsTrustedClient(pipe, out var who))
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
        { "settings.set", "quarantine.restore", "quarantine.delete", "scan.cancel", "trust.remove" };

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
                    AutoUpdate = _state.Settings.AutoUpdate,
                    BadUrls = _state.Engine.Blocklist.Count,
                    LastUpdate = _state.State.LastUpdate,
                    WatchedFolders = _realtime.WatchedFolders,
                    Signatures = _state.Engine.Signatures.Count,
                    Rules = _state.Engine.Rules.Rules.Count,
                    QuarantineCount = _state.Quarantine.List().Count,
                    ThreatsLast30Days = _state.Events.Recent(1000, true).Count(e => e.Date > DateTimeOffset.Now.AddDays(-30)),
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
                // the user says the file is safe, so trust it -
                // otherwise real-time protection would grab it again right away
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
                // where updates come from and which keys they're checked with can only be
                // changed by editing settings.json as an administrator
                s.UpdateUrl = _state.Settings.UpdateUrl;
                s.ExtraUpdateKeys = _state.Settings.ExtraUpdateKeys;
                _state.UpdateSettings(s);
                return Response.Success(s);

            default:
                return Response.Fail($"unknown command: {req.Cmd}");
        }
    }
}
