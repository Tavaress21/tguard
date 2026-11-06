using System;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using TGuard.App.Services;
using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;
using TGuard.Core.Security;
using TGuard.Core.Storage;

namespace TGuard.App.Views;

public static class Palette
{
    public static Brush B(string key) => (Brush)Application.Current.Resources[key];

    public static (Brush Bg, Brush Fg, string Label) ForVerdict(string verdict) => verdict switch
    {
        "malicious" => (B("BadSoft"), B("Bad"), Verdict.Malicious.Label()),
        "suspicious" => (B("WarnSoft"), B("Warn"), Verdict.Suspicious.Label()),
        _ => (B("GoodSoft"), B("Good"), Verdict.Clean.Label()),
    };

    public static (Brush Bg, Brush Fg, string Icon) ForCheck(CheckStatus s) => s switch
    {
        CheckStatus.Ok => (B("GoodSoft"), B("Good"), Glyph.Check),
        CheckStatus.Info => (B("InfoSoft"), B("Info"), Glyph.Info),
        CheckStatus.Warning => (B("WarnSoft"), B("Warn"), Glyph.Warning),
        _ => (B("BadSoft"), B("Bad"), Glyph.Cancel),
    };

    public static string Ago(DateTimeOffset? d)
    {
        if (d is null) return S.T("never");
        var span = DateTimeOffset.Now - d.Value;
        if (Loc.IsEnglish)
            return span.TotalMinutes < 1 ? "now" : span.TotalHours < 1 ? $"{(int)span.TotalMinutes} min ago" :
                   span.TotalDays < 1 ? $"{(int)span.TotalHours} h ago" : d.Value.ToString("dd/MM/yyyy HH:mm");
        return span.TotalMinutes < 1 ? "agora" : span.TotalHours < 1 ? $"há {(int)span.TotalMinutes} min" :
               span.TotalDays < 1 ? $"há {(int)span.TotalHours} h" : d.Value.ToString("dd/MM/yyyy HH:mm");
    }
}

public sealed class EventRow
{
    public EventRow(SecurityEvent e)
    {
        var (bg, fg, label) = Palette.ForVerdict(e.Verdict);
        PillBackground = bg; PillForeground = fg; VerdictLabel = label;
        Glyph = e.Verdict == "clean" ? Services.Glyph.Check : e.Verdict == "malicious" ? Services.Glyph.Shield : Services.Glyph.Warning;
        Title = System.IO.Path.GetFileName(e.Target) is { Length: > 0 } n ? n : e.Target;
        Subtitle = string.IsNullOrEmpty(e.Action) ? e.Headline : $"{e.Headline} · {e.Action}";
        Path = e.Target;
        When = Palette.Ago(e.Date);
        Source = e.Source switch
        {
            "realtime" => Loc.Pick("Tempo real", "Real-time"),
            "email" => "Email",
            "scan" => Loc.Pick("Análise", "Scan"),
            _ => e.Source,
        };
        Reasons = string.Join("\n", e.Reasons.Select(r => "• " + r));
    }

    public Brush PillBackground { get; }
    public Brush PillForeground { get; }
    public string VerdictLabel { get; }
    public string Glyph { get; }
    public string Title { get; }
    public string Subtitle { get; }
    public string Path { get; }
    public string When { get; }
    public string Source { get; }
    public string Reasons { get; }
}

public sealed class ThreatRow
{
    public ThreatRow(ThreatInfo t)
    {
        var (bg, fg, label) = Palette.ForVerdict(t.Verdict);
        PillBackground = bg; PillForeground = fg; VerdictLabel = $"{label} · {t.Score}";
        Glyph = t.Verdict == "malicious" ? Services.Glyph.Shield : Services.Glyph.Warning;
        Title = System.IO.Path.GetFileName(t.Path);
        Subtitle = string.IsNullOrEmpty(t.Action) ? t.Name : $"{t.Name} · {t.Action}";
        Path = t.Path;
        Reasons = string.Join("\n", t.Reasons.Select(r => "• " + r));
    }

    public Brush PillBackground { get; }
    public Brush PillForeground { get; }
    public string VerdictLabel { get; }
    public string Glyph { get; }
    public string Title { get; }
    public string Subtitle { get; }
    public string Path { get; }
    public string Reasons { get; }
}

public sealed class QuarantineRow
{
    public QuarantineRow(QuarantineItem q)
    {
        Id = q.Id;
        Sha256 = q.Sha256;
        Title = System.IO.Path.GetFileName(q.OriginalPath);
        Path = q.OriginalPath;
        Threat = q.Threat;
        When = q.Date.ToString("dd/MM/yyyy HH:mm");
        Size = q.Size < 1024 * 1024 ? $"{q.Size / 1024.0:0.#} KB" : $"{q.Size / 1048576.0:0.#} MB";
        Reasons = string.Join("\n", q.Reasons.Select(r => "• " + r));
    }

    public string Id { get; }
    public string Sha256 { get; }
    public string Title { get; }
    public string Path { get; }
    public string Threat { get; }
    public string When { get; }
    public string Size { get; }
    public string Reasons { get; }
}

public sealed class CheckRow
{
    public CheckRow(CheckItem c)
    {
        var (bg, fg, icon) = Palette.ForCheck(c.Status);
        Background = bg; Foreground = fg; Icon = icon;
        Title = c.Title; Detail = c.Detail; Fix = c.Fix;
        FixVisibility = string.IsNullOrEmpty(c.Fix) ? Visibility.Collapsed : Visibility.Visible;
    }

    public Brush Background { get; }
    public Brush Foreground { get; }
    public string Icon { get; }
    public string Title { get; }
    public string Detail { get; }
    public string Fix { get; }
    public Visibility FixVisibility { get; }
}

public sealed class ModuleRow
{
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Status { get; init; } = "";
    public Brush StatusBackground { get; init; } = Brushes.Transparent;
    public Brush StatusForeground { get; init; } = Brushes.Black;
    public string Glyph { get; init; } = "";
}
