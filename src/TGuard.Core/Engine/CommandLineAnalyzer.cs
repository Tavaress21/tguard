using System.Text;
using System.Text.RegularExpressions;
using TGuard.Core.Rules;

namespace TGuard.Core.Engine;

public static class CommandLineAnalyzer
{
    public static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe",
        "forfiles.exe", "schtasks.exe", "curl.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    };

    private static readonly Regex EncodedArg = new(
        @"(?:^|\s)[-/]([a-z]+)\s+['""]?([A-Za-z0-9+/=]{16,})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ScriptPath = new(
        @"(?:""([^""]+\.(?:ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd|sct|dll|msi))""|(\S+\.(?:ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd|sct|dll|msi)))(?=\s|$|,)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string? DecodePowerShell(string commandLine)
    {
        foreach (Match m in EncodedArg.Matches(commandLine))
        {
            // PowerShell accepts any prefix of -EncodedCommand (-e, -enc, -ec...)
            var flag = m.Groups[1].Value.ToLowerInvariant();
            if (flag != "ec" && !"encodedcommand".StartsWith(flag, StringComparison.Ordinal)) continue;
            try { return Encoding.Unicode.GetString(Convert.FromBase64String(m.Groups[2].Value)); }
            catch (FormatException) { }
        }
        return null;
    }

    public static List<string> ReferencedFiles(string commandLine)
    {
        var list = new List<string>();
        foreach (Match m in ScriptPath.Matches(commandLine))
        {
            var p = (m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).Trim('"', '\'', ',');
            p = Environment.ExpandEnvironmentVariables(p);
            var rooted = Regex.IsMatch(p, @"^([A-Za-z]:\\|\\\\)");   // C:\... or \\server\...
            if (rooted && !list.Contains(p, StringComparer.OrdinalIgnoreCase)) list.Add(p);
        }
        return list;
    }

    public static ScanResult Analyze(ScanEngine engine, string imageName, string commandLine)
    {
        var decoded = DecodePowerShell(commandLine);
        var text = decoded is null ? commandLine : commandLine + "\n" + decoded;
        var r = new ScanResult { Name = imageName, Kind = FileKind.Script };
        foreach (var rule in engine.Rules.Scan(RuleEngine.ToLatin1(Encoding.UTF8.GetBytes(text)), "script"))
        {
            r.Findings.Add(new(rule.Def.Score, rule.Description, "rule:" + rule.Def.Name));
            if (rule.Def.Score >= engine.Settings.ThresholdMalicious) r.ThreatName ??= $"TGuard.{rule.Def.Name}";
        }
        if (decoded is not null)
            r.Findings.Add(new(0, Loc.Pick("Comando PowerShell escondido em Base64 (descodificado e analisado)",
                                            "PowerShell command hidden in Base64 (decoded and scanned)"), "cmdline"));
        // URLs on the command line (mshta http://..., certutil -urlcache ...)
        foreach (Match m in Regex.Matches(text, @"https?://[^\s""'<>]+", RegexOptions.IgnoreCase))
            foreach (var f in engine.Urls.Analyze(m.Value))
                if (!r.Findings.Any(x => x.Message == f.Message)) r.Findings.Add(f);

        r.Score = ScanEngine.Combine(r.Findings.Select(f => f.Score));
        r.Verdict = engine.VerdictFor(r.Score);
        if (r.Verdict == Verdict.Malicious)
            r.ThreatName ??= r.Findings.Where(f => f.Source.StartsWith("rule:")).OrderByDescending(f => f.Score)
                                .Select(f => "TGuard." + f.Source[5..]).FirstOrDefault() ?? "TGuard.Heur.CommandLine";
        return r;
    }
}
