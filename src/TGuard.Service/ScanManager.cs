using System.Text.Json;
using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;

namespace TGuard.Service;

public sealed class ScanManager
{
    private readonly ServiceState _state;
    private readonly Notifier _notifier;
    private readonly ILogger<ScanManager> _log;
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;

    private ScanProgress? _current;

    public ScanProgress? Current => _current?.Snapshot();

    public bool Running => _current is { Running: true };

    public ScanManager(ServiceState state, Notifier notifier, ILogger<ScanManager> log)
    {
        _state = state;
        _notifier = notifier;
        _log = log;
    }

    public ScanProgress Start(string type, List<string>? customPaths = null)
    {
        lock (_lock)
        {
            if (_current is { Running: true }) return _current.Snapshot();
            var targets = type switch
            {
                "full" => UserFolders.FullScanTargets(),
                "custom" => (customPaths ?? new()).Where(p => Directory.Exists(p) || File.Exists(p)).Select(p => (p, int.MaxValue)).ToList(),
                _ => UserFolders.QuickScanTargets(),
            };
            _cts = new CancellationTokenSource();
            _current = new ScanProgress { Id = Guid.NewGuid().ToString("N")[..8], Type = type, Running = true, Started = DateTimeOffset.Now };
            var progress = _current;
            var ct = _cts.Token;
            _ = Task.Run(() => Run(progress, targets, ct));
            return progress.Snapshot();
        }
    }

    public void Cancel() { lock (_lock) _cts?.Cancel(); }

    private void Run(ScanProgress p, List<(string Path, int Depth)> targets, CancellationToken ct)
    {
        var lastPush = DateTime.MinValue;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var (root, depth) in targets)
            foreach (var file in _state.Engine.EnumerateFiles(root, ct, depth))
            {
                if (!seen.Add(file)) continue;
                p.CurrentFile = file;
                var r = _state.Engine.ScanFile(file, ct: ct);
                p.FilesScanned++;
                var t = _state.Handle(r, "scan");
                if (t is not null) { p.Threats++; lock (p.Found) p.Found.Add(t); }
                if ((DateTime.UtcNow - lastPush).TotalMilliseconds > 400)
                {
                    lastPush = DateTime.UtcNow;
                    Push("scan-progress", p);
                }
            }
        }
        catch (OperationCanceledException) { p.Cancelled = true; }
        catch (Exception ex) { _log.LogError(ex, "Scan failed"); }
        p.Running = false;
        p.Finished = DateTimeOffset.Now;
        p.CurrentFile = "";
        if (!p.Cancelled)
        {
            _state.State.LastScan = p.Finished;
            _state.State.LastScanType = p.Type;
            _state.State.Save();
        }
        _log.LogInformation("{Type} scan finished: {Files} files, {Threats} threats", p.Type, p.FilesScanned, p.Threats);
        Push("scan-done", p, Loc.Pick("Análise concluída", "Scan complete"),
            p.Threats == 0
                ? Loc.Pick($"{p.FilesScanned} ficheiros analisados. Nenhuma ameaça encontrada.", $"{p.FilesScanned} files scanned. No threats found.")
                : Loc.Pick($"{p.FilesScanned} ficheiros analisados. {p.Threats} ameaça(s) encontrada(s).", $"{p.FilesScanned} files scanned. {p.Threats} threat(s) found."));
    }

    private void Push(string kind, ScanProgress p, string title = "", string message = "") =>
        _notifier.Publish(new Notification { Kind = kind, Title = title, Message = message, Data = JsonSerializer.SerializeToNode(p.Snapshot(), Protocol.Json) });
}
