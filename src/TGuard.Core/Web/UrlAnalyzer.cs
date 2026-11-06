using System.Net;
using System.Text.RegularExpressions;
using TGuard.Core.Engine;

namespace TGuard.Core.Web;

public sealed class UrlAnalyzer
{
    private static readonly Regex UrlRx = new(@"https?://[^\s<>""'\)\]]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HrefRx = new(@"<a\b[^>]*?href\s*=\s*[""']?([^""'\s>]+)[^>]*>(.*?)</a>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    public static readonly HashSet<string> Shorteners = new(StringComparer.OrdinalIgnoreCase)
    { "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
      "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "shorturl.gg", "v.gd" };

    public static readonly HashSet<string> RiskyTlds = new(StringComparer.OrdinalIgnoreCase)
    { "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest", "cam",
      "icu", "monster", "sbs", "cfd", "lol", "quest", "buzz", "cyou", "bond" };

    public static readonly string[] FreeHosting =
    { "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app", "pages.dev", "workers.dev",
      "glitch.me", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "netlify.app", "vercel.app", "blogspot.com",
      "ipfs.io", "dweb.link", "r2.dev", "duckdns.org", "github.io", "square.site", "webflow.io", "framer.app" };

    public static readonly Dictionary<string, string> Brands = new(StringComparer.OrdinalIgnoreCase)
    {
        ["paypal"] = "paypal.com", ["microsoft"] = "microsoft.com", ["office365"] = "office.com",
        ["outlook"] = "outlook.com", ["apple"] = "apple.com", ["icloud"] = "icloud.com", ["google"] = "google.com",
        ["amazon"] = "amazon.com", ["netflix"] = "netflix.com", ["facebook"] = "facebook.com",
        ["instagram"] = "instagram.com", ["whatsapp"] = "whatsapp.com", ["fedex"] = "fedex.com",
        ["caixadirecta"] = "cgd.pt", ["millenniumbcp"] = "millenniumbcp.pt", ["millennium"] = "millenniumbcp.pt",
        ["novobanco"] = "novobanco.pt", ["santander"] = "santander.pt", ["bancobpi"] = "bancobpi.pt",
        ["mbway"] = "mbway.pt", ["portaldasfinancas"] = "portaldasfinancas.gov.pt", ["financas"] = "portaldasfinancas.gov.pt",
        ["seg-social"] = "seg-social.pt", ["segsocial"] = "seg-social.pt", ["vodafone"] = "vodafone.pt",
        ["activobank"] = "activobank.pt", ["montepio"] = "montepio.pt", ["creditoagricola"] = "creditoagricola.pt",
        ["linkedin"] = "linkedin.com", ["docusign"] = "docusign.com", ["dropbox"] = "dropbox.com",
        ["binance"] = "binance.com", ["coinbase"] = "coinbase.com", ["steam"] = "steampowered.com",
        ["correios"] = "ctt.pt", ["ctt-expresso"] = "ctt.pt", ["worten"] = "worten.pt", ["continente"] = "continente.pt",
        ["viaverde"] = "viaverde.pt", ["caixageral"] = "cgd.pt", ["bancoctt"] = "bancoctt.pt",
    };

    private static readonly Dictionary<char, char> Homoglyphs = new()
    { ['0'] = 'o', ['1'] = 'l', ['3'] = 'e', ['4'] = 'a', ['5'] = 's', ['7'] = 't', ['$'] = 's', ['@'] = 'a' };

    private static readonly HashSet<string> SecondLevel = new() { "co", "com", "gov", "org", "net", "edu", "ac" };

    private readonly Func<string, bool>? _isBlocklisted;

    public UrlAnalyzer(Func<string, bool>? isBlocklisted = null) => _isBlocklisted = isBlocklisted;

    public static string RegisteredDomain(string host)
    {
        var parts = host.ToLowerInvariant().Trim('.').Split('.');
        if (parts.Length >= 3 && SecondLevel.Contains(parts[^2]) && parts[^1].Length == 2)
            return string.Join('.', parts[^3..]);
        return parts.Length >= 2 ? string.Join('.', parts[^2..]) : host.ToLowerInvariant();
    }

    public static int Levenshtein(string a, string b)
    {
        var prev = Enumerable.Range(0, b.Length + 1).ToArray();
        for (int i = 1; i <= a.Length; i++)
        {
            var cur = new int[b.Length + 1];
            cur[0] = i;
            for (int j = 1; j <= b.Length; j++)
                cur[j] = Math.Min(Math.Min(prev[j] + 1, cur[j - 1] + 1), prev[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
            prev = cur;
        }
        return prev[b.Length];
    }

    public static List<(string Href, string Anchor)> ExtractLinks(string? text, string? html)
    {
        var list = new List<(string, string)>();
        if (!string.IsNullOrEmpty(html))
        {
            foreach (Match m in HrefRx.Matches(html))
                list.Add((WebUtility.HtmlDecode(m.Groups[1].Value), Regex.Replace(m.Groups[2].Value, "<[^>]+>", "").Trim()));
            foreach (Match m in UrlRx.Matches(html)) list.Add((WebUtility.HtmlDecode(m.Value), ""));
        }
        if (!string.IsNullOrEmpty(text))
            foreach (Match m in UrlRx.Matches(text)) list.Add((m.Value, ""));
        return list.Distinct().ToList();
    }

    public List<Finding> Analyze(string url, string anchorText = "")
    {
        var r = new List<Finding>();
        url = url.Trim();
        var schemeEnd = url.IndexOf(':');
        if (schemeEnd > 0)
        {
            var scheme = url[..schemeEnd].ToLowerInvariant();
            if (scheme is "javascript" or "data" or "vbscript") { r.Add(new(40, Loc.T("url.scheme", scheme), "url")); return r; }
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "http" && u.Scheme != "https")) return r;
        var host = u.IdnHost.ToLowerInvariant();
        if (host.Length == 0) return r;
        var shortUrl = url.Length < 90 ? url : url[..87] + "...";

        if (_isBlocklisted?.Invoke(url) == true) r.Add(new(90, Loc.T("url.blocklist", shortUrl), "url"));
        if (IPAddress.TryParse(host.Trim('[', ']'), out _)) r.Add(new(30, Loc.T("url.ip", shortUrl), "url"));
        if (!string.IsNullOrEmpty(u.UserInfo)) r.Add(new(35, Loc.T("url.at", shortUrl), "url"));
        if (host.Contains("xn--")) r.Add(new(30, Loc.T("url.punycode", host), "url"));
        if (Shorteners.Contains(host)) r.Add(new(10, Loc.T("url.short", host), "url"));
        var tld = host[(host.LastIndexOf('.') + 1)..];
        if (RiskyTlds.Contains(tld)) r.Add(new(15, Loc.T("url.tld", tld, host), "url"));
        if (FreeHosting.Any(f => host == f || host.EndsWith("." + f))) r.Add(new(15, Loc.T("url.freehost", host), "url"));
        if (host.Count(c => c == '.') >= 4) r.Add(new(10, Loc.T("url.subdomains", host), "url"));
        if (u.Scheme == "http" && Regex.IsMatch(url, "login|signin|verify|account|password|conta|senha|pagamento|entrar", RegexOptions.IgnoreCase))
            r.Add(new(15, Loc.T("url.http_login", shortUrl), "url"));

        var reg = RegisteredDomain(host);
        var regLabel = reg.Split('.')[0].Replace("-", "");
        var normalized = new string(host.Select(c => Homoglyphs.TryGetValue(c, out var n) ? n : c).Where(c => c != '-').ToArray());
        var isOfficial = Brands.Values.Any(o => reg == o || host.EndsWith("." + o));
        foreach (var (brand, official) in isOfficial ? Enumerable.Empty<KeyValuePair<string, string>>() : Brands)
        {
            var b = brand.Replace("-", "");
            if (b.Length >= 5 && normalized.Contains(b))
            { r.Add(new(35, Loc.T("url.brand", brand, official, host), "url")); break; }
            if (b.Length >= 5 && regLabel.Length >= 4 && Levenshtein(regLabel, b) == 1)
            { r.Add(new(45, Loc.T("url.typo", official, host), "url")); break; }
        }

        if (!string.IsNullOrWhiteSpace(anchorText))
        {
            var m = Regex.Match(anchorText.ToLowerInvariant(), @"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})");
            if (m.Success)
            {
                var shown = RegisteredDomain(m.Groups[1].Value);
                if (shown != reg) r.Add(new(40, Loc.T("url.mismatch", m.Groups[1].Value, host), "url"));
            }
        }
        return r;
    }
}
