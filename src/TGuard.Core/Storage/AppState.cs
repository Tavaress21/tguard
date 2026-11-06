using System.Text.Json;

namespace TGuard.Core.Storage;

public sealed class AppState
{
    public DateTimeOffset? LastScan { get; set; }
    public string? LastScanType { get; set; }
    public DateOnly? LastScheduledScan { get; set; }
    public DateTimeOffset? LastUpdate { get; set; }

    private static string PathOf => System.IO.Path.Combine(TGuardPaths.Root, "state.json");
    private static readonly object Lock = new();

    public static AppState Load()
    {
        lock (Lock)
        {
            try
            {
                if (File.Exists(PathOf)) return JsonSerializer.Deserialize<AppState>(File.ReadAllText(PathOf)) ?? new();
            }
            catch (Exception ex) when (ex is JsonException or IOException) { }
            return new();
        }
    }

    public void Save()
    {
        lock (Lock)
        {
            Directory.CreateDirectory(TGuardPaths.Root);
            var tmp = PathOf + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this));
            File.Move(tmp, PathOf, true);
        }
    }
}

public sealed class TrustedFile
{
    public string Sha256 { get; set; } = "";
    public string Path { get; set; } = "";
    public DateTimeOffset Date { get; set; }
}

public sealed class TrustStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private Dictionary<string, TrustedFile> _items = new(StringComparer.OrdinalIgnoreCase);

    public event Action? Changed;

    public TrustStore(string? path = null)
    {
        _path = path ?? System.IO.Path.Combine(TGuardPaths.Root, "trusted.json");
        try
        {
            if (File.Exists(_path))
                foreach (var t in JsonSerializer.Deserialize<List<TrustedFile>>(File.ReadAllText(_path)) ?? new())
                    _items[t.Sha256] = t;
        }
        catch (Exception ex) when (ex is JsonException or IOException) { }
    }

    public bool IsTrusted(string sha256) { lock (_lock) return _items.ContainsKey(sha256); }

    public List<TrustedFile> List() { lock (_lock) return _items.Values.OrderByDescending(t => t.Date).ToList(); }

    public void Add(string sha256, string path)
    {
        lock (_lock)
        {
            _items[sha256.ToLowerInvariant()] = new TrustedFile { Sha256 = sha256.ToLowerInvariant(), Path = path, Date = DateTimeOffset.Now };
            Save();
        }
        Changed?.Invoke();
    }

    public void Remove(string sha256)
    {
        lock (_lock) { _items.Remove(sha256); Save(); }
        Changed?.Invoke();
    }

    private void Save()
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, JsonSerializer.Serialize(_items.Values.ToList(), new JsonSerializerOptions { WriteIndented = true }));
    }
}

public static class Schedule
{
    public static bool IsQuickScanDue(TGuardSettings s, AppState st, DateTime now) =>
        s.ScheduledQuickScan
        && now.Hour >= s.ScheduledQuickScanHour
        && st.LastScheduledScan != DateOnly.FromDateTime(now);
}
