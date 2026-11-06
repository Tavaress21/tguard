using System.Text.Json;

namespace TGuard.Core.Storage;

public sealed class SecurityEvent
{
    public DateTimeOffset Date { get; set; } = DateTimeOffset.Now;
    public string Source { get; set; } = "";
    public string Target { get; set; } = "";
    public string Verdict { get; set; } = "";
    public int Score { get; set; }
    public string Headline { get; set; } = "";
    public List<string> Reasons { get; set; } = new();
    public string Action { get; set; } = "";
}

public sealed class EventStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private const long MaxBytes = 10 * 1024 * 1024;

    public event Action<SecurityEvent>? Added;

    public EventStore(string? path = null) => _path = path ?? TGuardPaths.Events;

    public void Add(SecurityEvent e)
    {
        var line = JsonSerializer.Serialize(e) + "\n";
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            if (File.Exists(_path) && new FileInfo(_path).Length > MaxBytes)
                File.Move(_path, _path + ".old", true);
            File.AppendAllText(_path, line);
        }
        Added?.Invoke(e);
    }

    public List<SecurityEvent> Recent(int max = 200, bool onlyThreats = false)
    {
        lock (_lock)
        {
            if (!File.Exists(_path)) return new();
            var result = new List<SecurityEvent>();
            foreach (var line in File.ReadLines(_path).Reverse())
            {
                SecurityEvent? e;
                try { e = JsonSerializer.Deserialize<SecurityEvent>(line); } catch (JsonException) { continue; }
                if (e is null || (onlyThreats && e.Verdict == "clean")) continue;
                result.Add(e);
                if (result.Count >= max) break;
            }
            return result;
        }
    }
}
