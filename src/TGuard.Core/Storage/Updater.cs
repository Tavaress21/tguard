using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TGuard.Core.Engine;
using TGuard.Core.Rules;

namespace TGuard.Core.Storage;

public sealed class UpdateReport
{
    public int SignaturesAdded { get; set; }
    public int UrlsAdded { get; set; }
    public int RulesLoaded { get; set; }
    public List<string> Sources { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public bool Success => Sources.Count > 0;
}

public sealed class Updater
{
    // Since mid-2025 abuse.ch needs a free Auth-Key (https://auth.abuse.ch/).
    public const string MalwareBazaarRecent = "https://mb-api.abuse.ch/v2/files/exports/{0}/recent.csv";
    public const string UrlhausRecent = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/";

    private readonly HttpClient _http;

    public Updater(HttpMessageHandler? handler = null)
    {
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromSeconds(90);
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("TGuard",
            typeof(Updater).Assembly.GetName().Version?.ToString(3) ?? "0"));
    }

    public async Task<UpdateReport> RunAsync(ScanEngine engine, TGuardSettings settings, CancellationToken ct = default)
    {
        var report = new UpdateReport();

        // 1) TGuard update server (manifest.json lists the files)
        if (!string.IsNullOrWhiteSpace(settings.UpdateUrl))
        {
            try
            {
                var baseUri = new Uri(settings.UpdateUrl.EndsWith('/') ? settings.UpdateUrl : settings.UpdateUrl + "/");
                var manifest = JsonSerializer.Deserialize<UpdateManifest>(await GetTextAsync(new Uri(baseUri, "manifest.json"), null, ct),
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? new();
                if (manifest.Signatures is { Length: > 0 })
                    report.SignaturesAdded += AddHashes(engine, await GetTextAsync(new Uri(baseUri, manifest.Signatures), null, ct), "TGuard");
                if (manifest.Urls is { Length: > 0 })
                    report.UrlsAdded += AddUrls(engine, await GetTextAsync(new Uri(baseUri, manifest.Urls), null, ct));
                if (manifest.Rules is { Length: > 0 })
                    report.RulesLoaded += InstallRules(engine, await GetTextAsync(new Uri(baseUri, manifest.Rules), null, ct));
                report.Sources.Add("TGuard");
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or UriFormatException or FormatException or ArgumentException or InvalidDataException)
            {
                report.Errors.Add($"TGuard: {ex.Message}");
            }
        }

        // 2) abuse.ch feeds (MalwareBazaar, URLhaus), only with an Auth-Key
        var key = settings.AbuseChAuthKey?.Trim();
        if (string.IsNullOrEmpty(key))
        {
            report.Notes.Add("abuse.ch: no Auth-Key configured, skipped");
        }
        else
        {
            try
            {
                var url = new Uri(string.Format(MalwareBazaarRecent, Uri.EscapeDataString(key)));
                report.SignaturesAdded += AddHashes(engine, await GetTextAsync(url, null, ct), "MalwareBazaar");
                report.Sources.Add("MalwareBazaar");
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException)
            { report.Errors.Add($"MalwareBazaar: {ex.Message}"); }
            try
            {
                report.UrlsAdded += AddUrlhausJson(engine, await GetTextAsync(new Uri(UrlhausRecent), key, ct));
                report.Sources.Add("URLhaus");
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException or JsonException)
            { report.Errors.Add($"URLhaus: {ex.Message}"); }
        }

        if (report.UrlsAdded > 0) engine.Blocklist.Save(TGuardPaths.UrlBlocklist);
        if (report.SignaturesAdded > 0 || report.UrlsAdded > 0 || report.RulesLoaded > 0) engine.InvalidateCache();
        return report;
    }

    private async Task<string> GetTextAsync(Uri uri, string? authKey, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        if (authKey is not null) req.Headers.Add("Auth-Key", authKey);
        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        if (bytes.Length > 4 && bytes[0] == 'P' && bytes[1] == 'K')
        {
            using var z = new ZipArchive(new MemoryStream(bytes));
            using var sr = new StreamReader(z.Entries[0].Open());
            return await sr.ReadToEndAsync(ct);
        }
        return Encoding.UTF8.GetString(bytes);
    }

    private static readonly System.Text.RegularExpressions.Regex Sha256Rx = new(@"\b[a-fA-F0-9]{64}\b");

    /// <summary>
    /// Accepts plain lists ("hash" or "hash;name") and the MalwareBazaar CSV export
    /// (hash in column 2, malware family in column 9). Lines starting with # are skipped.
    /// </summary>
    public static int AddHashes(ScanEngine engine, string text, string source)
    {
        var items = new List<(string, string)>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length < 64 || line[0] == '#') continue;
            var m = Sha256Rx.Match(line);
            if (!m.Success) continue;
            string name = $"{source}.Malware";
            if (line.Contains("\",\""))
            {
                var cols = line.Trim('"').Split("\",\"");
                if (cols.Length > 8 && cols[8].Trim() is { Length: > 0 } sig && sig != "n/a") name = $"{source}.{sig}";
            }
            else if (line.IndexOf(';') is var i and > 0 && i + 1 < line.Length) name = line[(i + 1)..].Trim();
            items.Add((m.Value, name));
        }
        return engine.Signatures.AddRange(items);
    }

    public static int AddUrlhausJson(ScanEngine engine, string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("urls", out var urls) || urls.ValueKind != JsonValueKind.Array) return 0;
        var list = urls.EnumerateArray()
            .Select(u => u.TryGetProperty("url", out var v) ? v.GetString() : null)
            .Where(u => !string.IsNullOrEmpty(u))
            .Select(u => u!)
            .ToList();
        var before = engine.Blocklist.Count;
        engine.Blocklist.Add(list);
        return engine.Blocklist.Count - before;
    }

    public static int AddUrls(ScanEngine engine, string text)
    {
        var urls = text.Split('\n').Select(l => l.Trim())
            .Where(l => l.Length > 0 && l[0] != '#' && (l.StartsWith("http://") || l.StartsWith("https://") || l.StartsWith("host:")))
            .ToList();
        var before = engine.Blocklist.Count;
        engine.Blocklist.Add(urls);
        return engine.Blocklist.Count - before;
    }

    public static int InstallRules(ScanEngine engine, string json)
    {
        var defs = JsonSerializer.Deserialize<List<RuleDefinition>>(json) ?? new();
        var compiled = defs.Select(RuleEngine.Compile).ToList();   // throws if any rule is invalid
        Directory.CreateDirectory(TGuardPaths.UserRules);
        File.WriteAllText(Path.Combine(TGuardPaths.UserRules, "tguard-update.json"), json);
        engine.ReloadRules();
        return compiled.Count;
    }

    private sealed class UpdateManifest
    {
        public string? Signatures { get; set; }
        public string? Urls { get; set; }
        public string? Rules { get; set; }
    }
}
