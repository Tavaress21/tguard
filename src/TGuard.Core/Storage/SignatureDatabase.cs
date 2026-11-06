using System.Security.Cryptography;
using System.Text;

namespace TGuard.Core.Storage;

public sealed class SignatureDatabase
{
    private readonly Dictionary<string, string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _allowed = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private readonly string? _path;
    private readonly string? _allowPath;

    public const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    public SignatureDatabase(string? path = null, string? allowPath = null)
    {
        _path = path;
        _allowPath = allowPath;
        _hashes[EicarSha256] = "EICAR-Test-File";
        if (path is not null && File.Exists(path)) LoadFile(path);
        if (allowPath is not null && File.Exists(allowPath))
            foreach (var line in File.ReadLines(allowPath))
                if (line.Trim() is { Length: 64 } h && IsHex(h)) _allowed.Add(h.ToLowerInvariant());
    }

    public int Count { get { lock (_lock) return _hashes.Count; } }

    public int AllowedCount { get { lock (_lock) return _allowed.Count; } }

    public string? Lookup(string sha256)
    {
        lock (_lock) return !_allowed.Contains(sha256) && _hashes.TryGetValue(sha256, out var n) ? n : null;
    }

    public bool IsAllowed(string sha256)
    {
        lock (_lock) return _allowed.Contains(sha256) && !sha256.Equals(EicarSha256, StringComparison.OrdinalIgnoreCase);
    }

    public int Allow(IEnumerable<string> hashes)
    {
        lock (_lock)
        {
            int added = 0;
            foreach (var raw in hashes)
            {
                var h = raw.Trim();
                if (h.Length == 64 && IsHex(h) && !h.Equals(EicarSha256, StringComparison.OrdinalIgnoreCase) && _allowed.Add(h.ToLowerInvariant())) added++;
            }
            if (added > 0 && _allowPath is not null)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_allowPath)!);
                var tmp = _allowPath + ".tmp";
                File.WriteAllLines(tmp, _allowed);
                File.Move(tmp, _allowPath, true);
            }
            return added;
        }
    }

    public int AddRange(IEnumerable<(string Hash, string Name)> items, bool persist = true)
    {
        int added = 0;
        var newLines = new StringBuilder();
        lock (_lock)
        {
            foreach (var (h, n) in items)
            {
                if (h.Length != 64 || !IsHex(h)) continue;
                if (_hashes.TryAdd(h.ToLowerInvariant(), n)) { added++; newLines.Append(h.ToLowerInvariant()).Append(';').Append(n).Append('\n'); }
            }
            if (persist && _path is not null && added > 0)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                File.AppendAllText(_path, newLines.ToString());
            }
        }
        return added;
    }

    private void LoadFile(string path)
    {
        foreach (var line in File.ReadLines(path))
        {
            if (line.Length < 64 || line[0] == '#') continue;
            var sep = line.IndexOf(';');
            var h = sep > 0 ? line[..sep] : line.Trim();
            if (h.Length == 64) _hashes[h] = sep > 0 ? line[(sep + 1)..] : "Malware";
        }
    }

    private static bool IsHex(string s) => s.All(Uri.IsHexDigit);

    public static string Sha256Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}

public sealed class UrlBlocklist
{
    private readonly HashSet<string> _urls = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public UrlBlocklist(string? path = null)
    {
        if (path is not null && File.Exists(path))
            foreach (var l in File.ReadLines(path)) AddInternal(l.Trim());
    }

    public int Count { get { lock (_lock) return _urls.Count + _hosts.Count; } }

    private void AddInternal(string entry)
    {
        if (entry.Length == 0 || entry[0] == '#') return;
        if (entry.StartsWith("host:", StringComparison.Ordinal)) _hosts.Add(entry[5..]);
        else _urls.Add(entry);
    }

    public void Add(IEnumerable<string> entries) { lock (_lock) foreach (var e in entries) AddInternal(e); }

    public void Save(string path)
    {
        lock (_lock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            File.WriteAllLines(tmp, _urls.Concat(_hosts.Select(h => "host:" + h)));
            File.Move(tmp, path, true);
        }
    }

    public bool Contains(string url)
    {
        lock (_lock)
        {
            if (_urls.Contains(url)) return true;
            if (_hosts.Count == 0 || !Uri.TryCreate(url, UriKind.Absolute, out var u)) return false;
            var host = u.Host.TrimEnd('.');
            while (true)
            {
                if (_hosts.Contains(host)) return true;
                var dot = host.IndexOf('.');
                if (dot < 0 || host.IndexOf('.', dot + 1) < 0) return false;
                host = host[(dot + 1)..];
            }
        }
    }
}
