using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Compression;
using TGuard.Core.Analyzers;
using TGuard.Core.Rules;
using TGuard.Core.Security;
using TGuard.Core.Storage;
using TGuard.Core.Web;

namespace TGuard.Core.Engine;

public sealed class ScanEngine
{
    public SignatureDatabase Signatures { get; }
    public RuleEngine Rules { get; private set; }
    public TrustStore Trust { get; }
    public UrlBlocklist Blocklist { get; }
    public UrlAnalyzer Urls { get; }

    private TGuardSettings _settings;
    public TGuardSettings Settings
    {
        get => _settings;
        set { _settings = value; InvalidateCache(); }
    }

    public bool UseWindowsContext { get; set; } = true;

    // Results cache keyed by path + size + mtime.
    private readonly ConcurrentDictionary<string, (long Size, DateTime Modified, ScanResult Result)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private const int CacheLimit = 50_000;

    public ScanEngine(TGuardSettings settings, SignatureDatabase signatures, RuleEngine rules,
                      TrustStore? trust = null, UrlBlocklist? blocklist = null)
    {
        _settings = settings;
        Signatures = signatures;
        Rules = rules;
        Trust = trust ?? new TrustStore(Path.Combine(Path.GetTempPath(), $"tguard-trust-{Guid.NewGuid():N}.json"));
        Blocklist = blocklist ?? new UrlBlocklist();
        Urls = new UrlAnalyzer(Blocklist.Contains);
        Trust.Changed += InvalidateCache;
    }

    public static ScanEngine CreateDefault(TGuardSettings? settings = null) =>
        new(settings ?? TGuardSettings.Load(), new SignatureDatabase(TGuardPaths.Signatures),
            RuleEngine.LoadDefault(new[] { TGuardPaths.UserRules }), new TrustStore(), new UrlBlocklist(TGuardPaths.UrlBlocklist));

    public void InvalidateCache() => _cache.Clear();

    public void ReloadRules()
    {
        Rules = RuleEngine.LoadDefault(new[] { TGuardPaths.UserRules });
        InvalidateCache();
    }

    private long MaxBytes => (long)Settings.MaxFileSizeMb * 1024 * 1024;

    public Verdict VerdictFor(int score) =>
        score >= Settings.ThresholdMalicious ? Verdict.Malicious :
        score >= Settings.ThresholdSuspicious ? Verdict.Suspicious : Verdict.Clean;

    public static int Combine(IEnumerable<int> scores)
    {
        var s = scores.Where(x => x > 0).OrderByDescending(x => x).ToList();
        if (s.Count == 0) return 0;
        return Math.Min(100, s[0] + s.Skip(1).Sum() / 2);
    }

    public ScanResult ScanFile(string path, bool fromEmail = false, CancellationToken ct = default)
    {
        var r = new ScanResult { Name = path };
        try
        {
            var info = new FileInfo(path);
            r.Size = info.Length;
            if (info.Length > MaxBytes) { r.Error = Loc.T("file.toobig"); return r; }
            var modified = info.LastWriteTimeUtc;
            if (!fromEmail && _cache.TryGetValue(path, out var c) && c.Size == info.Length && c.Modified == modified)
                return c.Result;

            byte[] data;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                data = new byte[fs.Length];
                fs.ReadExactly(data);
            }
            var res = ScanBytes(data, Path.GetFileName(path), 0, fromEmail, ct);
            var result = new ScanResult
            {
                Name = path, Sha256 = res.Sha256, Size = res.Size, Kind = res.Kind, Score = res.Score,
                Verdict = res.Verdict, ThreatName = res.ThreatName,
            }.WithFindings(res);

            if (!Trust.IsTrusted(result.Sha256) && UseWindowsContext) ApplyFileContext(result, path);

            if (!fromEmail)
            {
                if (_cache.Count > CacheLimit) _cache.Clear();
                _cache[path] = (info.Length, modified, result);
            }
            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            r.Error = Loc.T("file.noaccess", ex.Message);
            return r;
        }
    }

    /// <summary>
    /// Weighs where a file came from. Scripts, shortcuts and disk images straight from the
    /// Internet are rarely legitimate, so they count more than a downloaded installer.
    /// </summary>
    public void ApplyOrigin(ScanResult r, WebOrigin origin)
    {
        if (!origin.FromInternet) return;
        var weight = r.Kind switch
        {
            FileKind.Script or FileKind.Lnk or FileKind.Iso or FileKind.Jar => 20,
            FileKind.Pe or FileKind.Html => 10,
            _ => r.Findings.Any(f => f.Score > 0) ? 10 : 0,
        };
        if (weight == 0) return;
        var host = Uri.TryCreate(origin.HostUrl ?? origin.ReferrerUrl, UriKind.Absolute, out var u) ? u.Host : "?";
        r.Findings.Add(new(weight, Loc.T("origin.internet", host), "origin"));
        foreach (var url in new[] { origin.HostUrl, origin.ReferrerUrl }.Where(x => !string.IsNullOrEmpty(x)).Distinct())
            foreach (var f in Urls.Analyze(url!))
                if (!r.Findings.Any(x => x.Message == f.Message)) r.Findings.Add(f with { Source = "origin" });
        Rescore(r, false);
    }

    private void ApplyFileContext(ScanResult r, string path)
    {
        var origin = FileContext.ReadWebOrigin(path);
        if (origin is not null) ApplyOrigin(r, origin);

        var trustedSigner = false;
        var microsoft = false;
        // signature checks are slow-ish, only do them when they can change the verdict
        if (r.Kind == FileKind.Pe && r.Findings.Any(f => f.Score > 0 && f.Source != "signature"))
        {
            var sig = FileContext.VerifySignature(path);
            switch (sig.State)
            {
                case SignatureState.Valid:
                    trustedSigner = true;
                    microsoft = sig.IsMicrosoft;
                    r.Findings.Add(new(0, Loc.T("sig.valid", sig.Signer ?? "?"), "signature-ok"));
                    r.Findings.RemoveAll(f => f.Message == Loc.T("pe.unsigned"));
                    break;
                case SignatureState.Invalid:
                    r.Findings.Add(new(45, Loc.T("sig.invalid"), "signature-bad"));
                    break;
                case SignatureState.Untrusted:
                    r.Findings.Add(new(15, Loc.T("sig.untrusted", sig.Signer ?? "?"), "signature-bad"));
                    break;
            }
        }
        Rescore(r, trustedSigner, microsoft);
    }

    private void Rescore(ScanResult r, bool trustedSigner, bool microsoft = false)
    {
        var own = Combine(r.Findings.Select(f => f.Score));
        var childMax = r.Children.Count > 0 ? r.Children.Max(c => c.Score) : 0;
        var score = Combine(new[] { own, childMax });
        var hardHit = r.Findings.Any(f => f.Source == "signature" || (f.Source.StartsWith("rule:") && f.Score >= Settings.ThresholdMalicious));
        if (trustedSigner && !hardHit) score = microsoft ? 0 : Math.Max(0, score - 35);
        r.Score = score;
        r.Verdict = VerdictFor(score);
        if (r.Verdict == Verdict.Clean) r.ThreatName = null;
        else if (r.Verdict == Verdict.Malicious) r.ThreatName ??= $"TGuard.Heur.{r.Kind}";
    }

    public ScanResult ScanBytes(byte[] data, string name, int depth = 0, bool fromEmail = false, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var r = new ScanResult { Name = name, Size = data.Length, Sha256 = SignatureDatabase.Sha256Hex(data) };

        // 0) user-trusted file
        if (Trust.IsTrusted(r.Sha256))
        {
            r.Kind = FileTypeDetector.Detect(data, name);
            r.Findings.Add(new(0, Loc.T("trust.file"), "trusted"));
            return r;
        }

        // 1) known signature
        var sig = Signatures.Lookup(r.Sha256);
        if (sig is not null)
        {
            r.ThreatName = sig;
            r.Findings.Add(new(100, Loc.T("sig.known", sig), "signature"));
        }

        // 2) real file type + heuristics
        r.Kind = FileTypeDetector.Detect(data, name);
        r.Findings.AddRange(Heuristics.Name(name, r.Kind, fromEmail));
        switch (r.Kind)
        {
            case FileKind.Pe: r.Findings.AddRange(Heuristics.Pe(data)); break;
            case FileKind.OfficeOle or FileKind.OfficeOpenXml or FileKind.Rtf: r.Findings.AddRange(Heuristics.Office(data, r.Kind)); break;
            case FileKind.Pdf: r.Findings.AddRange(Heuristics.Pdf(data)); break;
            case FileKind.Script or FileKind.Html: r.Findings.AddRange(Heuristics.Script(data)); break;
        }

        // 3) rules (for OLE documents, also run on the decompressed VBA source)
        var category = RuleEngine.CategoryOf(r.Kind);
        if (category != "archive")
        {
            // rules look at the first and last 8 MB: enough for scripts and droppers, and keeps
            // big installers from taking seconds per file
            const int Window = 8 * 1024 * 1024;
            var text = data.Length <= 2 * Window
                ? RuleEngine.ToLatin1(data)
                : RuleEngine.ToLatin1(data.AsSpan(0, Window)) + "\n" + RuleEngine.ToLatin1(data.AsSpan(data.Length - Window));
            if (r.Kind is FileKind.Pe or FileKind.Lnk or FileKind.OfficeOle or FileKind.Data)
                text += "\n" + Heuristics.ExtractWideStrings(data.AsSpan(0, Math.Min(data.Length, 2 * Window)));
            if (r.Kind == FileKind.OfficeOle)
            {
                var vba = Heuristics.ExtractVbaSource(data);
                if (vba.Length > 0) text += "\n" + RuleEngine.ToLatin1(vba);
            }
            foreach (var rule in Rules.Scan(text, category))
            {
                r.Findings.Add(new(rule.Def.Score, rule.Description, "rule:" + rule.Def.Name));
                r.ThreatName ??= rule.Def.Score >= Settings.ThresholdMalicious ? $"TGuard.{rule.Def.Name}" : null;
            }
        }

        // 4) archives: scan the contents
        if (data.Length >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4
            && r.Kind is FileKind.Zip or FileKind.Jar or FileKind.OfficeOpenXml)
            ScanZip(data, r, depth, fromEmail, ct);

        var own = Combine(r.Findings.Select(f => f.Score));
        var childMax = r.Children.Count > 0 ? r.Children.Max(c => c.Score) : 0;
        r.Score = Combine(new[] { own, childMax });
        r.Verdict = VerdictFor(r.Score);
        if (r.Verdict == Verdict.Malicious && r.ThreatName is null)
            r.ThreatName = r.Children.Where(c => c.Verdict == Verdict.Malicious).Select(c => c.ThreatName).FirstOrDefault(n => n != null)
                           ?? $"TGuard.Heur.{r.Kind}";
        return r;
    }

    private void ScanZip(byte[] data, ScanResult r, int depth, bool fromEmail, CancellationToken ct)
    {
        if (depth >= Settings.ArchiveMaxDepth) { r.Findings.Add(new(10, Loc.T("zip.deep"))); return; }
        if (r.Kind == FileKind.Zip && HasEncryptedEntries(data)) { r.Findings.Add(new(35, Loc.T("zip.encrypted"))); return; }
        try
        {
            using var z = new ZipArchive(new MemoryStream(data, false), ZipArchiveMode.Read);
            var entries = z.Entries.Where(e => !e.FullName.EndsWith('/')).ToList();
            if (entries.Count > Settings.ArchiveMaxEntries)
            {
                r.Findings.Add(new(10, Loc.T("zip.many", entries.Count)));
                entries = entries.Take(Settings.ArchiveMaxEntries).ToList();
            }
            long total = 0;
            foreach (var e in entries)
            {
                ct.ThrowIfCancellationRequested();
                if (e.Length > MaxBytes) continue;
                if (e.CompressedLength > 0 && e.Length / (double)e.CompressedLength > 1000 && e.Length > 10_000_000)
                { r.Findings.Add(new(40, Loc.T("zip.bomb"))); return; }
                total += e.Length;
                if (total > MaxBytes * 4) break;
                // inside Office docs only code parts and relationships matter
                if (r.Kind == FileKind.OfficeOpenXml &&
                    !e.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) &&
                    !e.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase) &&
                    !FileTypeDetector.ExecExt.Contains(Path.GetExtension(e.FullName)) &&
                    !FileTypeDetector.ScriptExt.Contains(Path.GetExtension(e.FullName)))
                    continue;
                using var s = e.Open();
                using var ms = new MemoryStream((int)Math.Min(e.Length, int.MaxValue));
                s.CopyTo(ms);
                r.Children.Add(ScanBytes(ms.ToArray(), e.FullName, depth + 1, fromEmail, ct));
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or NotSupportedException or IOException)
        {
            r.Findings.Add(new(5, Loc.T("zip.bad")));
        }
    }

    public static bool HasEncryptedEntries(ReadOnlySpan<byte> d)
    {
        ReadOnlySpan<byte> sig = "PK\x01\x02"u8;
        int i = 0;
        while (i < d.Length - 46)
        {
            var rel = d[i..].IndexOf(sig);
            if (rel < 0) break;
            i += rel;
            var flags = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(i + 8, 2));
            if ((flags & 1) != 0) return true;
            i += 4;
        }
        return false;
    }

    public IEnumerable<string> EnumerateFiles(string root, CancellationToken ct = default, int maxDepth = int.MaxValue)
    {
        if (File.Exists(root)) { yield return root; yield break; }
        var exclusions = Settings.Exclusions.Select(TGuardSettings.Expand).ToList();
        var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint, MaxRecursionDepth = maxDepth };
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(root, "*", opts); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { yield break; }
        foreach (var f in files)
        {
            ct.ThrowIfCancellationRequested();
            if (exclusions.Any(e => f.StartsWith(e, StringComparison.OrdinalIgnoreCase))) continue;
            if (f.StartsWith(TGuardPaths.Root, StringComparison.OrdinalIgnoreCase)) continue;
            yield return f;
        }
    }
}

internal static class ScanResultExt
{
    public static ScanResult WithFindings(this ScanResult target, ScanResult source)
    {
        target.Findings.AddRange(source.Findings);
        target.Children.AddRange(source.Children);
        return target;
    }
}
