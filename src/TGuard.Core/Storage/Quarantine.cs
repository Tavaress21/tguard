using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace TGuard.Core.Storage;

public sealed class QuarantineItem
{
    public string Id { get; set; } = "";
    public DateTimeOffset Date { get; set; }
    public string OriginalPath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public string Threat { get; set; } = "";
    public List<string> Reasons { get; set; } = new();
    public bool PendingReboot { get; set; }
}

public sealed class Quarantine
{
    private readonly string _dir;
    private readonly byte[] _key;
    private readonly object _lock = new();
    private string IndexPath => Path.Combine(_dir, "index.json");

    public Quarantine(string? dir = null)
    {
        _dir = dir ?? TGuardPaths.QuarantineDir;
        Directory.CreateDirectory(_dir);
        var keyPath = Path.Combine(_dir, "quarantine.key");
        if (!File.Exists(keyPath)) File.WriteAllBytes(keyPath, RandomNumberGenerator.GetBytes(32));
        _key = File.ReadAllBytes(keyPath);
    }

    public List<QuarantineItem> List()
    {
        lock (_lock)
        {
            if (!File.Exists(IndexPath)) return new();
            try { return JsonSerializer.Deserialize<List<QuarantineItem>>(File.ReadAllText(IndexPath)) ?? new(); }
            catch (JsonException) { return new(); }
        }
    }

    private void SaveIndex(List<QuarantineItem> items)
    {
        var tmp = IndexPath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, IndexPath, true);
    }

    public QuarantineItem Isolate(string path, string threat, IEnumerable<string> reasons)
    {
        byte[] data;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            data = new byte[fs.Length];
            fs.ReadExactly(data);
        }
        var item = Store(data, path, threat, reasons);
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try { File.Move(path, path + ".tguard-bloqueado", true); }
            catch (Exception ex2) when (ex2 is IOException or UnauthorizedAccessException)
            {
                if (!OperatingSystem.IsWindows() || !MoveFileEx(path, null, 4)) throw;
                item.PendingReboot = true;
                lock (_lock)
                {
                    var items = List();
                    var i = items.FindIndex(x => x.Id == item.Id);
                    if (i >= 0) { items[i] = item; SaveIndex(items); }
                }
            }
        }
        return item;
    }

    public QuarantineItem Store(byte[] data, string label, string threat, IEnumerable<string> reasons)
    {
        var item = new QuarantineItem
        {
            Id = Guid.NewGuid().ToString("N"),
            Date = DateTimeOffset.Now,
            OriginalPath = label,
            Sha256 = SignatureDatabase.Sha256Hex(data),
            Size = data.Length,
            Threat = threat,
            Reasons = reasons.Take(30).ToList(),
        };
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var cipher = new byte[data.Length];
        using (var aes = new AesGcm(_key, 16)) aes.Encrypt(nonce, data, cipher, tag);
        using (var fs = File.Create(Path.Combine(_dir, item.Id + ".tgq")))
        {
            fs.Write("TGQ1"u8);
            fs.Write(nonce);
            fs.Write(tag);
            fs.Write(cipher);
        }
        lock (_lock)
        {
            var items = List();
            items.Insert(0, item);
            SaveIndex(items);
        }
        return item;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string existing, string? replacement, int flags);

    public byte[] ReadDecrypted(string id)
    {
        var blob = File.ReadAllBytes(Path.Combine(_dir, id + ".tgq"));
        if (blob.Length < 32 || blob[0] != 'T' || blob[1] != 'G' || blob[2] != 'Q' || blob[3] != '1')
            throw new InvalidDataException("Invalid quarantine file");
        var nonce = blob.AsSpan(4, 12);
        var tag = blob.AsSpan(16, 16);
        var cipher = blob.AsSpan(32);
        var plain = new byte[cipher.Length];
        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    public string Restore(string id, string? destination = null)
    {
        var item = List().FirstOrDefault(i => i.Id == id) ?? throw new KeyNotFoundException(id);
        var data = ReadDecrypted(id);
        if (SignatureDatabase.Sha256Hex(data) != item.Sha256) throw new InvalidDataException("Quarantine file is corrupted");
        var dest = destination ?? item.OriginalPath;
        if (dest.StartsWith("email:", StringComparison.Ordinal) || !Path.IsPathRooted(dest))
        {
            var pub = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "..", "Downloads");
            dest = Path.Combine(Path.GetFullPath(pub), string.Concat(Path.GetFileName(item.OriginalPath).Split(Path.GetInvalidFileNameChars())));
        }
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        if (File.Exists(dest)) dest = Path.Combine(Path.GetDirectoryName(dest)!,
            $"{Path.GetFileNameWithoutExtension(dest)} (reposto){Path.GetExtension(dest)}");
        File.WriteAllBytes(dest, data);
        Delete(id);
        return dest;
    }

    public void Delete(string id)
    {
        lock (_lock)
        {
            var items = List();
            items.RemoveAll(i => i.Id == id);
            SaveIndex(items);
            var f = Path.Combine(_dir, id + ".tgq");
            if (File.Exists(f)) File.Delete(f);
        }
    }
}
