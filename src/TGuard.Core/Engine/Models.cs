namespace TGuard.Core.Engine;

public enum Verdict { Clean = 0, Suspicious = 1, Malicious = 2 }

public enum FileKind { Data, Pe, Elf, Pdf, Lnk, OfficeOle, OfficeOpenXml, Rtf, Zip, Jar, Iso, Html, Script }

public sealed record Finding(int Score, string Message, string Source = "heuristic");

public sealed class ScanResult
{
    public required string Name { get; init; }
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public FileKind Kind { get; set; } = FileKind.Data;
    public int Score { get; set; }
    public Verdict Verdict { get; set; } = Verdict.Clean;
    public List<Finding> Findings { get; } = new();
    public List<ScanResult> Children { get; } = new();
    public string? Error { get; set; }
    public string? ThreatName { get; set; }

    public IEnumerable<string> AllReasons(string prefix = "")
    {
        foreach (var f in Findings.OrderByDescending(f => f.Score))
            yield return f.Score > 0 ? $"{prefix}{f.Message} (+{f.Score})" : $"{prefix}{f.Message}";
        foreach (var c in Children.Where(c => c.Verdict != Verdict.Clean))
            foreach (var r in c.AllReasons($"{prefix}{c.Name} › "))
                yield return r;
    }

    public string Headline()
    {
        if (ThreatName is not null) return ThreatName;
        var worst = Findings.OrderByDescending(f => f.Score).FirstOrDefault();
        var child = Children.OrderByDescending(c => c.Score).FirstOrDefault();
        if (child is not null && (worst is null || child.Score > worst.Score))
            return child.Headline();
        return worst?.Message ?? "";
    }
}

public static class VerdictExtensions
{
    public static string Label(this Verdict v) => v switch
    {
        Verdict.Malicious => Loc.T("verdict.malicious"),
        Verdict.Suspicious => Loc.T("verdict.suspicious"),
        _ => Loc.T("verdict.clean"),
    };
}
