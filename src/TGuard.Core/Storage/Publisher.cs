using System.Text;
using System.Text.Json;
using TGuard.Core.Security;

namespace TGuard.Core.Storage;

/// <summary>
/// Builds the signed files served by the update server. Runs in GitHub Actions
/// (the private keys only exist there as secrets), never on users' PCs.
/// </summary>
public static class Publisher
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private const int MaxSignatures = 400_000;
    private const int MaxUrls = 150_000;

    /// <summary>
    /// Refreshes signatures.txt / urls.txt from abuse.ch plus our own lists, keeping what was
    /// already published (lists only grow until they hit the cap), then signs feeds.json.
    /// </summary>
    public static async Task<Updater.FeedsManifest> BuildFeedsAsync(
        string outDir, string feedsKeyPem, string? abuseChKey,
        IEnumerable<string> ownHashLists, IEnumerable<string> ownUrlLists, string? rulesJson,
        IEnumerable<string>? ownAllowLists = null, HttpMessageHandler? handler = null, Action<string>? log = null, CancellationToken ct = default)
    {
        log ??= _ => { };
        Directory.CreateDirectory(outDir);
        var sigPath = Path.Combine(outDir, "signatures.txt");
        var urlPath = Path.Combine(outDir, "urls.txt");

        // hash -> name, newest last
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in ReadLines(sigPath))
        {
            var parts = line.Split(';', 2);
            if (parts[0].Length == 64) hashes[parts[0]] = parts.Length > 1 ? parts[1] : "Malware";
        }
        var urls = new List<string>(ReadLines(urlPath));
        var urlSet = new HashSet<string>(urls, StringComparer.OrdinalIgnoreCase);

        void AddHash(string h, string name) { if (h.Length == 64 && h.All(Uri.IsHexDigit)) hashes[h.ToLowerInvariant()] = name; }
        void AddUrl(string u) { if (urlSet.Add(u)) urls.Add(u); }

        foreach (var list in ownHashLists)
            foreach (var line in list.Split('\n').Select(l => l.Trim()).Where(l => l.Length >= 64 && l[0] != '#'))
            {
                var parts = line.Split(';', 2);
                AddHash(parts[0].Trim(), parts.Length > 1 ? parts[1].Trim() : "TGuard.Malware");
            }
        foreach (var list in ownUrlLists)
            foreach (var line in list.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && l[0] != '#'))
                AddUrl(line);

        if (!string.IsNullOrWhiteSpace(abuseChKey))
        {
            var engine = new Engine.ScanEngine(new TGuardSettings(), new SignatureDatabase(), new Rules.RuleEngine());
            var http = new Updater(handler);
            var key = abuseChKey.Trim();
            try
            {
                var csv = Encoding.UTF8.GetString(await http.GetBytesAsync(new Uri(string.Format(Updater.MalwareBazaarRecent, Uri.EscapeDataString(key))), ct));
                var before = hashes.Count;
                foreach (var raw in csv.Split('\n'))
                {
                    var line = raw.Trim();
                    if (line.Length < 64 || line[0] == '#' || !line.Contains("\",\"")) continue;
                    var cols = line.Trim('"').Split("\",\"");
                    if (cols.Length < 2) continue;
                    var family = cols.Length > 8 && cols[8] is { Length: > 0 } f && f != "n/a" ? f : "Malware";
                    AddHash(cols[1], "MalwareBazaar." + family);
                }
                log($"MalwareBazaar: +{hashes.Count - before}");
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { log($"MalwareBazaar failed: {ex.Message}"); }
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, Updater.UrlhausRecent);
                req.Headers.Add("Auth-Key", key);
                using var client = handler is null ? new HttpClient() : new HttpClient(handler, false);
                using var resp = await client.SendAsync(req, ct);
                resp.EnsureSuccessStatusCode();
                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                var before = urls.Count;
                if (doc.RootElement.TryGetProperty("urls", out var arr))
                    foreach (var u in arr.EnumerateArray())
                        if (u.TryGetProperty("url", out var v) && v.GetString() is { Length: > 0 } s) AddUrl(s);
                log($"URLhaus: +{urls.Count - before}");
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException) { log($"URLhaus failed: {ex.Message}"); }
        }
        else log("abuse.ch: no key, only TGuard lists published");

        var allowed = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var list in ownAllowLists ?? Enumerable.Empty<string>())
            foreach (var line in list.Split('\n').Select(l => l.Trim().ToLowerInvariant()))
                if (line.Length == 64 && line.All(Uri.IsHexDigit) && line != SignatureDatabase.EicarSha256) allowed.Add(line);
        foreach (var h in allowed) hashes.Remove(h);

        var sigLines = hashes.Skip(Math.Max(0, hashes.Count - MaxSignatures)).Select(kv => $"{kv.Key};{kv.Value}");
        var urlLines = urls.Skip(Math.Max(0, urls.Count - MaxUrls));
        await File.WriteAllLinesAsync(sigPath, new[] { "# TGuard signatures (sha256;name)" }.Concat(sigLines), ct);
        await File.WriteAllLinesAsync(urlPath, new[] { "# TGuard malicious URLs" }.Concat(urlLines), ct);

        var manifest = new Updater.FeedsManifest
        {
            Generated = DateTimeOffset.UtcNow,
            Signatures = FileEntry(sigPath),
            Urls = FileEntry(urlPath),
        };
        var allowPath = Path.Combine(outDir, "allow.txt");
        if (allowed.Count > 0)
        {
            await File.WriteAllLinesAsync(allowPath, new[] { "# TGuard safe files (sha256)" }.Concat(allowed), ct);
            manifest.Allow = FileEntry(allowPath);
        }
        else if (File.Exists(allowPath)) File.Delete(allowPath);
        if (!string.IsNullOrWhiteSpace(rulesJson))
        {
            // refuse to publish rules that don't compile
            foreach (var d in JsonSerializer.Deserialize<List<Rules.RuleDefinition>>(rulesJson) ?? new()) Rules.RuleEngine.Compile(d);
            var rulesPath = Path.Combine(outDir, "rules.json");
            await File.WriteAllTextAsync(rulesPath, rulesJson, ct);
            manifest.Rules = FileEntry(rulesPath);
        }
        WriteSigned(Path.Combine(outDir, "feeds.json"), JsonSerializer.SerializeToUtf8Bytes(manifest, Json), feedsKeyPem);
        log($"feeds.json: {hashes.Count} signatures, {urls.Count} urls, {allowed.Count} safe files");
        return manifest;
    }

    /// <summary>Copies the installer next to a signed app.json describing it.</summary>
    public static AppRelease PublishApp(string installerPath, string version, string notes, string outDir, string releaseKeyPem)
    {
        Directory.CreateDirectory(outDir);
        var name = Path.GetFileName(installerPath);
        var target = Path.Combine(outDir, name);
        if (!Path.GetFullPath(installerPath).Equals(Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
            File.Copy(installerPath, target, true);
        foreach (var old in Directory.GetFiles(outDir, "TGuard-Setup-*.exe").Where(f => !f.EndsWith(name, StringComparison.OrdinalIgnoreCase)))
            File.Delete(old);
        var bytes = File.ReadAllBytes(target);
        var release = new AppRelease { Version = version, File = name, Sha256 = SignatureDatabase.Sha256Hex(bytes), Size = bytes.Length, Notes = notes };
        WriteSigned(Path.Combine(outDir, "app.json"), JsonSerializer.SerializeToUtf8Bytes(release, Json), releaseKeyPem);
        return release;
    }

    private static void WriteSigned(string path, byte[] content, string keyPem)
    {
        File.WriteAllBytes(path, content);
        File.WriteAllBytes(path + ".sig", UpdateSigning.Sign(content, keyPem));
    }

    private static Updater.FeedFile FileEntry(string path) =>
        new() { Name = Path.GetFileName(path), Sha256 = SignatureDatabase.Sha256Hex(File.ReadAllBytes(path)) };

    private static IEnumerable<string> ReadLines(string path) =>
        File.Exists(path) ? File.ReadLines(path).Select(l => l.Trim()).Where(l => l.Length > 0 && l[0] != '#') : Enumerable.Empty<string>();
}
