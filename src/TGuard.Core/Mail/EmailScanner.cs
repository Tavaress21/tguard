using TGuard.Core.Engine;
using TGuard.Core.Web;

namespace TGuard.Core.Mail;

public sealed class EmailFinding
{
    public string Subject { get; init; } = "";
    public string From { get; init; } = "";
    public int Score { get; set; }
    public Verdict Verdict { get; set; }
    public string ThreatName { get; set; } = "";
    public List<Finding> Findings { get; } = new();
    public List<(MimeAttachment Attachment, ScanResult Result)> BadAttachments { get; } = new();
}

public static class EmailScanner
{
    private const int MaxLinks = 200;

    public static EmailFinding Scan(ScanEngine engine, MimeMessage msg, CancellationToken ct = default)
    {
        var result = new EmailFinding { Subject = msg.Subject, From = msg.From };
        var scores = new List<int>();
        string? threat = null;

        foreach (var att in msg.Attachments)
        {
            ct.ThrowIfCancellationRequested();
            var r = engine.ScanBytes(att.Data, att.FileName, 0, fromEmail: true, ct);
            if (r.Verdict == Verdict.Clean) continue;
            result.BadAttachments.Add((att, r));
            scores.Add(r.Score);
            threat ??= r.ThreatName;
            foreach (var f in r.AllReasons().Take(3)) result.Findings.Add(new Finding(r.Score, $"{att.FileName}: {f}", "email"));
        }

        var linkScore = 0;
        foreach (var (href, anchor) in UrlAnalyzer.ExtractLinks(msg.Text, msg.Html).Take(MaxLinks))
        {
            var findings = engine.Urls.Analyze(href, anchor);
            if (findings.Count == 0) continue;
            var s = ScanEngine.Combine(findings.Select(f => f.Score));
            if (s <= linkScore) continue;
            linkScore = s;
            result.Findings.RemoveAll(f => f.Source == "email-link");
            foreach (var f in findings) result.Findings.Add(f with { Source = "email-link" });
        }
        if (linkScore > 0) scores.Add(linkScore);

        var sender = SenderFindings(msg);
        result.Findings.AddRange(sender);
        scores.AddRange(sender.Select(f => f.Score));

        result.Score = ScanEngine.Combine(scores);
        result.Verdict = engine.VerdictFor(result.Score);
        result.ThreatName = threat ?? (linkScore >= 40 ? "TGuard.Email.Phishing" : sender.Count > 0 ? "TGuard.Email.Spoofing" : "TGuard.Email.Suspicious");
        return result;
    }

    public static List<Finding> SenderFindings(MimeMessage msg)
    {
        var list = new List<Finding>();
        var from = msg.FromAddress;
        var domain = from.Contains('@') ? from[(from.IndexOf('@') + 1)..] : "";
        if (domain.Length == 0) return list;
        var reg = UrlAnalyzer.RegisteredDomain(domain);
        var display = msg.FromDisplayName.ToLowerInvariant().Replace(" ", "").Replace("-", "");

        var tokens = System.Text.RegularExpressions.Regex.Split(msg.FromDisplayName.ToLowerInvariant(), @"[^a-z0-9]+");
        if (!UrlAnalyzer.IsOfficialHost(domain))
        {
            foreach (var (brand, official) in UrlAnalyzer.Brands)
            {
                var b = brand.Replace("-", "");
                var hit = b.Length >= 5 ? display.Contains(b) : tokens.Contains(b);
                if (!hit) continue;
                list.Add(new Finding(35, Loc.T("mail.spoof", msg.FromDisplayName, from, official), "email"));
                break;
            }
        }

        if (display.Contains('@'))
        {
            var shown = MimeMessage.Address(msg.FromDisplayName);
            if (shown.Length > 0 && !shown.Equals(from, StringComparison.OrdinalIgnoreCase))
                list.Add(new Finding(30, Loc.T("mail.fakeaddress", shown, from), "email"));
        }

        var reply = msg.ReplyToAddress;
        if (reply.Contains('@'))
        {
            var replyReg = UrlAnalyzer.RegisteredDomain(reply[(reply.IndexOf('@') + 1)..]);
            if (replyReg != reg) list.Add(new Finding(10, Loc.T("mail.replyto", reply), "email"));
        }
        return list;
    }
}
