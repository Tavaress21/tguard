using System.Collections.Concurrent;
using TGuard.Core.Analyzers;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class RealtimeProtection : BackgroundService
{
    private static readonly string[] IgnoreSuffix = { ".crdownload", ".part", ".tmp", ".partial", ".download", ".!ut", ".tgq", ".opdownload" };

    private readonly ServiceState _state;
    private readonly ILogger<RealtimeProtection> _log;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, (DateTime Seen, long Size)> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, FileSystemWatcher> _drives = new(StringComparer.OrdinalIgnoreCase);

    public int WatchedFolders => _watchers.Count + _drives.Count;

    public RealtimeProtection(ServiceState state, ILogger<RealtimeProtection> log)
    {
        _state = state;
        _log = log;
        _state.SettingsChanged += Rebuild;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        Rebuild();
        var nextRefresh = DateTime.UtcNow.AddMinutes(10);
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(750, ct).ContinueWith(_ => { });
            ProcessPending(ct);
            if (DateTime.UtcNow > nextRefresh) { Rebuild(); nextRefresh = DateTime.UtcNow.AddMinutes(10); }
        }
        foreach (var w in _watchers) w.Dispose();
    }

    private void Rebuild()
    {
        lock (_watchers)
        {
            foreach (var w in _watchers) w.Dispose();
            _watchers.Clear();
            if (!_state.Settings.RealtimeEnabled) { _log.LogInformation("Real-time protection is off"); return; }
            foreach (var dir in UserFolders.Resolve(_state.Settings.WatchFolders))
            {
                var w = CreateWatcher(dir);
                if (w is not null) _watchers.Add(w);
            }
            _log.LogInformation("Real-time protection watching {Count} folders", _watchers.Count);
        }
    }

    private FileSystemWatcher? CreateWatcher(string dir)
    {
        try
        {
            var w = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            w.Created += (_, e) => Queue(e.FullPath);
            w.Changed += (_, e) => Queue(e.FullPath);
            w.Renamed += (_, e) => Queue(e.FullPath);
            w.Error += (_, e) => _log.LogWarning(e.GetException(), "Watcher for {Dir} dropped events", dir);
            w.EnableRaisingEvents = true;
            return w;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not watch {Dir}", dir);
            return null;
        }
    }

    public void AddDrive(string root)
    {
        if (!_state.Settings.RealtimeEnabled || _drives.ContainsKey(root)) return;
        var w = CreateWatcher(root);
        if (w is not null) _drives[root] = w;
    }

    public void RemoveDrive(string root)
    {
        if (_drives.TryRemove(root, out var w)) w.Dispose();
    }

    private void Queue(string path)
    {
        var lower = path.ToLowerInvariant();
        if (IgnoreSuffix.Any(lower.EndsWith) || lower.Contains("~$")) return;
        if (path.StartsWith(TGuardPaths.Root, StringComparison.OrdinalIgnoreCase)) return;
        if (_state.Settings.Exclusions.Any(e => path.StartsWith(Environment.ExpandEnvironmentVariables(e), StringComparison.OrdinalIgnoreCase))) return;
        _pending[path] = (DateTime.UtcNow, -1);
    }

    private void ProcessPending(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        foreach (var (path, (seen, lastSize)) in _pending.ToArray())
        {
            if ((now - seen).TotalMilliseconds < 1500) continue;
            long size;
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || (fi.Attributes & FileAttributes.Directory) != 0) { _pending.TryRemove(path, out _); continue; }
                size = fi.Length;
            }
            catch (Exception) { _pending.TryRemove(path, out _); continue; }

            if (size != lastSize) { _pending[path] = (now, size); continue; }
            _pending.TryRemove(path, out _);

            if (_recent.TryGetValue(path, out var t) && (now - t).TotalSeconds < 10) continue;
            _recent[path] = now;
            if (_recent.Count > 5000) foreach (var k in _recent.Where(kv => (now - kv.Value).TotalMinutes > 5).Select(kv => kv.Key).ToList()) _recent.TryRemove(k, out _);

            try
            {
                var r = _state.Engine.ScanFile(path, ct: ct);
                _state.Handle(r, "realtime");
            }
            catch (Exception ex) { _log.LogWarning(ex, "Error scanning {File}", path); }
        }
    }
}
