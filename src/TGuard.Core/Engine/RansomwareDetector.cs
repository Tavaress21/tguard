using System.Security.Cryptography;

namespace TGuard.Core.Engine;

public enum ChangeKind { Created, Changed, Renamed, Deleted }

public sealed class RansomwareDetector
{
    public const string CanaryPrefix = "!tguard-protegido";
    public static readonly string[] CanaryExtensions = { ".docx", ".xlsx", ".pdf", ".jpg" };

    private static readonly HashSet<string> KnownExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".pdf", ".txt", ".rtf", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".heic", ".webp", ".tif", ".tiff", ".raw", ".cr2", ".nef", ".psd", ".svg",
        ".mp3", ".wav", ".flac", ".m4a", ".ogg", ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".zip", ".rar", ".7z", ".tar", ".gz",
        ".html", ".htm", ".xml", ".json", ".md", ".log", ".ini", ".lnk", ".url", ".exe", ".msi", ".dll", ".iso", ".tmp", ".bak",
        ".crdownload", ".part", ".partial", ".download", ".db", ".sqlite", ".pst", ".ost", ".eml", ".msg", ".vcf", ".ics",
        ".epub", ".mobi", ".dwg", ".dxf", ".skp", ".blend", ".obj", ".fbx", ".stl", ".py", ".js", ".ts", ".cs", ".java",
        ".c", ".cpp", ".h", ".php", ".css", ".sql", ".yml", ".yaml", ".toml", ".ps1", ".bat", ".cmd", ".sh", ".odg", ".key",
        ".numbers", ".pages", ".indd", ".ai", ".eps", ".xcf", ".kra", ".mpp", ".vsd", ".vsdx", ".one", ".accdb", ".mdb",
    };

    private readonly Dictionary<string, string> _canaries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<(DateTime When, string Dir, string Ext)> _burst = new();
    private readonly object _lock = new();

    public int BurstThreshold { get; init; } = 12;
    public TimeSpan BurstWindow { get; init; } = TimeSpan.FromSeconds(20);

    public IReadOnlyCollection<string> Canaries { get { lock (_lock) return _canaries.Keys.ToList(); } }

    public static bool IsCanaryName(string path) =>
        Path.GetFileName(path).StartsWith(CanaryPrefix, StringComparison.OrdinalIgnoreCase);

    public static byte[] CanaryContent(string extension)
    {
        var body = RandomNumberGenerator.GetBytes(48 * 1024);
        byte[] header = extension.ToLowerInvariant() switch
        {
            ".docx" or ".xlsx" => new byte[] { 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00 },
            ".pdf" => "%PDF-1.7\n%âãÏÓ\n"u8.ToArray(),
            ".jpg" => new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00 },
            _ => Array.Empty<byte>(),
        };
        var data = new byte[header.Length + body.Length];
        header.CopyTo(data, 0);
        body.CopyTo(data, header.Length);
        return data;
    }

    public void Register(string path, byte[] content)
    {
        lock (_lock) _canaries[path] = Convert.ToHexString(SHA256.HashData(content));
    }

    public void Forget(string path)
    {
        lock (_lock) _canaries.Remove(path);
    }

    public bool IsCanary(string path)
    {
        lock (_lock) return _canaries.ContainsKey(path);
    }

    public string? OnChange(string path, ChangeKind kind, string? oldPath, DateTime now, Func<string, byte[]?> read)
    {
        lock (_lock)
        {
            if (kind == ChangeKind.Renamed && oldPath is not null && _canaries.ContainsKey(oldPath))
                return Loc.T("rw.canary.renamed", Path.GetFileName(oldPath), Path.GetFileName(path));

            if (kind == ChangeKind.Changed && _canaries.TryGetValue(path, out var hash))
            {
                var data = read(path);
                if (data is not null && !Convert.ToHexString(SHA256.HashData(data)).Equals(hash, StringComparison.OrdinalIgnoreCase))
                    return Loc.T("rw.canary.changed", Path.GetFileName(path));
            }

            var suspicious = kind switch
            {
                ChangeKind.Renamed => oldPath is not null && IsExtensionSwap(oldPath, path),
                ChangeKind.Created => IsAppendedExtension(path),
                ChangeKind.Deleted => _canaries.ContainsKey(path),
                _ => false,
            };
            if (!suspicious) return null;

            var dir = Path.GetDirectoryName(path) ?? "";
            var ext = Path.GetExtension(path);
            _burst.Enqueue((now, dir, ext));
            while (_burst.Count > 0 && now - _burst.Peek().When > BurstWindow) _burst.Dequeue();

            var sameExt = _burst.GroupBy(b => b.Ext, StringComparer.OrdinalIgnoreCase).Max(g => g.Count());
            if (_burst.Count >= BurstThreshold && sameExt >= BurstThreshold / 2)
            {
                var n = _burst.Count;
                _burst.Clear();
                return Loc.T("rw.burst", n, string.IsNullOrEmpty(ext) ? "?" : ext, (int)BurstWindow.TotalSeconds);
            }
            return null;
        }
    }

    public static bool IsExtensionSwap(string oldPath, string newPath)
    {
        var oldExt = Path.GetExtension(oldPath);
        var newExt = Path.GetExtension(newPath);
        if (oldExt.Equals(newExt, StringComparison.OrdinalIgnoreCase)) return false;
        if (KnownExtensions.Contains(newExt)) return false;
        return KnownExtensions.Contains(oldExt) || string.IsNullOrEmpty(oldExt);
    }

    public static bool IsAppendedExtension(string path)
    {
        var ext = Path.GetExtension(path);
        if (string.IsNullOrEmpty(ext) || KnownExtensions.Contains(ext)) return false;
        var inner = Path.GetExtension(Path.GetFileNameWithoutExtension(path));
        return !string.IsNullOrEmpty(inner) && KnownExtensions.Contains(inner);
    }
}
