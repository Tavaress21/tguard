using System.Collections.Concurrent;
using TGuard.Core.Analyzers;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class RealtimeProtection : BackgroundService
{
    private static readonly string[] IgnoreSuffix = { ".crdownload", ".part", ".tmp", ".partial", ".download", ".!ut", ".tgq", ".opdownload" };

    private static readonly string[] OutlookFolders =
    {
        "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache\\Content.Outlook",
        "%LOCALAPPDATA%\\Microsoft\\Olk\\Attachments",
        "%LOCALAPPDATA%\\Packages\\Microsoft.OutlookForWindows_8wekyb3d8bbwe\\LocalCache\\Microsoft\\Olk\\Attachments",
    };

    private readonly ServiceState _state;
    private readonly ILogger<RealtimeProtection> _log;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, (DateTime Seen, long Size)> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _retries = new(StringComparer.OrdinalIgnoreCase);
    private List<string> _folders = new();
    private List<string> _exclusions = new();
    private readonly ConcurrentDictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, FileSystemWatcher> _drives = new(StringComparer.OrdinalIgnoreCase);

    public int WatchedFolders { get { lock (_watchers) return _watchers.Count + _drives.Count; } }

    public event Action<string, WatcherChangeTypes, string?>? FileChanged;

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
            _exclusions = UserFolders.Expand(_state.Settings.Exclusions)
                .Select(e => e.TrimEnd('\\', '/')).Where(e => e.Length > 2).ToList();
            var patterns = _state.Settings.WatchFolders.ToList();
            if (_state.Settings.EmailProtection) patterns.AddRange(OutlookFolders);
            var wanted = _state.Settings.RealtimeEnabled ? UserFolders.Resolve(patterns) : new List<string>();
            if (wanted.Count == _folders.Count && wanted.All(f => _folders.Contains(f, StringComparer.OrdinalIgnoreCase)) && _watchers.Count == wanted.Count)
                return;
            foreach (var w in _watchers) w.Dispose();
            _watchers.Clear();
            _folders = wanted;
            if (!_state.Settings.RealtimeEnabled)
            {
                foreach (var d in _drives.Keys.ToList()) RemoveDrive(d);
                _log.LogInformation("Real-time protection is off");
                return;
            }
            foreach (var dir in wanted)
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
            w.Created += (_, e) => { Queue(e.FullPath); FileChanged?.Invoke(e.FullPath, e.ChangeType, null); };
            w.Changed += (_, e) => { Queue(e.FullPath); FileChanged?.Invoke(e.FullPath, e.ChangeType, null); };
            w.Renamed += (_, e) => { Queue(e.FullPath); FileChanged?.Invoke(e.FullPath, e.ChangeType, e.OldFullPath); };
            w.Deleted += (_, e) => FileChanged?.Invoke(e.FullPath, e.ChangeType, null);
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
        if (IsExcluded(path)) return;
        _pending[path] = (DateTime.UtcNow, -1);
    }

    private bool IsExcluded(string path)
    {
        foreach (var e in _exclusions)
            if (path.Equals(e, StringComparison.OrdinalIgnoreCase)
                || (path.StartsWith(e, StringComparison.OrdinalIgnoreCase) && path.Length > e.Length && path[e.Length] is '\\' or '/'))
                return true;
        return false;
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
                if (r.Error is not null && File.Exists(path))
                {
                    var n = _retries.AddOrUpdate(path, 1, (_, v) => v + 1);
                    if (n <= 20) { _recent.TryRemove(path, out _); _pending[path] = (now.AddSeconds(Math.Min(30, n * 2)), size); }
                    else _retries.TryRemove(path, out _);
                    continue;
                }
                _retries.TryRemove(path, out _);
                _state.Handle(r, "realtime");
            }
            catch (Exception ex) { _log.LogWarning(ex, "Error scanning {File}", path); }
        }
    }
}
