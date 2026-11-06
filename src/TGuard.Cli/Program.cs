using System.Diagnostics;
using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Security;
using TGuard.Core.Storage;

// tguard - command line interface
//   tguard scan <folder|file>... [--all] [--quarantine]
//   tguard quarantine [list|restore <id>|delete <id>]
//   tguard check
//   tguard update
//   tguard info

TGuardPaths.Ensure();
var settings = TGuardSettings.Load();
Loc.Language = args.Contains("--pt") ? "pt" : "en";
args = args.Where(a => a is not ("--pt" or "--en")).ToArray();

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    Console.WriteLine("""
        TGuard - free, open-source antivirus

          tguard scan <path>... [--all] [--quarantine]
          tguard quarantine list | restore <id> | delete <id>
          tguard check          PC security check
          tguard update         download the latest signatures
          tguard signature <file>   show Authenticode status
          tguard info
          (--pt for Portuguese output)
        """);
    return 0;
}

return args[0] switch
{
    "scan" or "analisar" => Scan(args.Skip(1).ToArray()),
    "quarantine" or "quarentena" => QuarantineCmd(args.Skip(1).ToArray()),
    "check" or "verificar-pc" => Check(),
    "update" or "atualizar" => Update(),
    "info" => Info(),
    "signature" => Signature(args.Skip(1).FirstOrDefault()),
    _ => Unknown(args[0]),
};

int Unknown(string cmd)
{
    Console.Error.WriteLine($"Unknown command: {cmd}");
    return 2;
}

int Scan(string[] a)
{
    var showAll = a.Contains("--all") || a.Contains("--todos");
    var quarantine = a.Contains("--quarantine") || a.Contains("--quarentena");
    var paths = a.Where(x => !x.StartsWith("--")).ToList();
    if (paths.Count == 0) { Console.Error.WriteLine("Give a folder or file to scan."); return 2; }

    var engine = ScanEngine.CreateDefault(settings);
    var q = quarantine ? new Quarantine() : null;
    var events = new EventStore();
    int total = 0, threats = 0;
    var sw = Stopwatch.StartNew();
    var self = AppContext.BaseDirectory;

    foreach (var p in paths)
    foreach (var f in engine.EnumerateFiles(Path.GetFullPath(p)))
    {
        if (f.StartsWith(self, StringComparison.OrdinalIgnoreCase)) continue;
        total++;
        var r = engine.ScanFile(f);
        if (r.Error is not null) continue;
        if (r.Verdict != Verdict.Clean)
        {
            threats++;
            var action = "";
            if (q is not null && r.Verdict == Verdict.Malicious)
            {
                try { action = "quarantined " + q.Isolate(f, r.ThreatName ?? "", r.AllReasons()).Id[..8]; }
                catch (Exception ex) { action = "quarantine failed: " + ex.Message; }
            }
            events.Add(new SecurityEvent { Source = "scan", Target = f, Verdict = r.Verdict.ToString().ToLowerInvariant(), Score = r.Score, Headline = r.Headline(), Reasons = r.AllReasons().ToList(), Action = action });
        }
        if (r.Verdict != Verdict.Clean || showAll) Print(r);
        if (total % 1000 == 0) Console.Error.WriteLine($"  ... {total} files");
    }
    Console.WriteLine($"\n{total} files scanned in {sw.Elapsed.TotalSeconds:0.0}s, {threats} threat(s).");
    return threats > 0 ? 1 : 0;
}

void Print(ScanResult r)
{
    var color = r.Verdict switch { Verdict.Malicious => ConsoleColor.Red, Verdict.Suspicious => ConsoleColor.Yellow, _ => ConsoleColor.Green };
    var old = Console.ForegroundColor;
    Console.ForegroundColor = color;
    Console.Write($"[{r.Verdict.ToString().ToUpperInvariant(),-10}]");
    Console.ForegroundColor = old;
    Console.WriteLine($" {r.Score,3}/100  {r.Name}");
    foreach (var reason in r.AllReasons()) Console.WriteLine($"               - {reason}");
}

int QuarantineCmd(string[] a)
{
    var q = new Quarantine();
    var sub = a.FirstOrDefault() ?? "list";
    switch (sub)
    {
        case "list" or "listar":
            var items = q.List();
            if (items.Count == 0) Console.WriteLine("Quarantine is empty.");
            foreach (var i in items)
                Console.WriteLine($"{i.Id[..8]}  {i.Date:yyyy-MM-dd HH:mm}  {i.Threat,-30} {i.OriginalPath}");
            return 0;
        case "restore" or "repor" or "delete" or "apagar":
            var item = q.List().FirstOrDefault(i => a.Length > 1 && i.Id.StartsWith(a[1], StringComparison.OrdinalIgnoreCase));
            if (item is null) { Console.Error.WriteLine("Item not found."); return 2; }
            if (sub is "restore" or "repor")
            {
                new TrustStore().Add(item.Sha256, item.OriginalPath);
                Console.WriteLine("Restored to: " + q.Restore(item.Id));
            }
            else { q.Delete(item.Id); Console.WriteLine("Deleted."); }
            return 0;
        default:
            Console.Error.WriteLine("Usage: quarantine list | restore <id> | delete <id>");
            return 2;
    }
}

int Check()
{
    foreach (var c in SecurityCheck.Run())
    {
        var icon = c.Status switch { CheckStatus.Ok => "OK  ", CheckStatus.Info => "INFO", CheckStatus.Warning => "WARN", _ => "FAIL" };
        Console.WriteLine($"[{icon}] {c.Title}: {c.Detail}");
        if (c.Fix.Length > 0) Console.WriteLine($"       -> {c.Fix}");
    }
    return 0;
}

int Update()
{
    var engine = ScanEngine.CreateDefault(settings);
    var rep = new Updater().RunAsync(engine, settings).GetAwaiter().GetResult();
    Console.WriteLine($"Sources: {(rep.Sources.Count == 0 ? "none" : string.Join(", ", rep.Sources))}");
    Console.WriteLine($"New signatures: {rep.SignaturesAdded}, new malicious URLs: {rep.UrlsAdded}, rules: {rep.RulesLoaded}");
    foreach (var e in rep.Errors) Console.WriteLine($"  ! {e}");
    if (rep.Success) { var st = AppState.Load(); st.LastUpdate = DateTimeOffset.Now; st.Save(); }
    return rep.Success ? 0 : 1;
}

int Signature(string? file)
{
    if (file is null || !File.Exists(file)) { Console.Error.WriteLine("File not found."); return 2; }
    var sig = FileContext.VerifySignature(file);
    Console.WriteLine($"{sig.State}{(sig.Signer is null ? "" : $" ({sig.Signer})")}");
    var origin = FileContext.ReadWebOrigin(file);
    if (origin is not null) Console.WriteLine($"Zone {origin.ZoneId}, from {origin.HostUrl ?? origin.ReferrerUrl ?? "?"}");
    return 0;
}

int Info()
{
    var engine = ScanEngine.CreateDefault(settings);
    Console.WriteLine($"TGuard {typeof(ScanEngine).Assembly.GetName().Version}");
    Console.WriteLine($"Data:         {TGuardPaths.Root}");
    Console.WriteLine($"Rules:        {engine.Rules.Rules.Count}");
    Console.WriteLine($"Signatures:   {engine.Signatures.Count}");
    Console.WriteLine($"Bad URLs:     {engine.Blocklist.Count}");
    Console.WriteLine($"Quarantine:   {new Quarantine().List().Count} item(s)");
    Console.WriteLine($"Last update:  {AppState.Load().LastUpdate?.ToString("yyyy-MM-dd HH:mm") ?? "never"}");
    return 0;
}
