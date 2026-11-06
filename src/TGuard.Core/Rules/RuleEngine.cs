using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TGuard.Core.Engine;

namespace TGuard.Core.Rules;

/*
 YARA-inspired rule format (the matcher itself is our own):
 {
   "name": "Ransomware_Shadow_Copy_Deletion",
   "description_en": "...", "description_pt": "...",
   "score": 90,
   "strings": {
     "a": { "text": "abc", "nocase": true },     // text (also matched as UTF-16LE)
     "b": { "hex": "4D 5A ?? 00" },             // bytes (?? = wildcard)
     "c": { "regex": "foo\\s+bar", "nocase": true }
   },
   "condition": "any" | "all" | "2" | "a and (b or not c)",
   "filetypes": ["pe","script","office","pdf","html","lnk","any"]
 }
*/

public sealed class RuleDefinition
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("description_pt")] public string DescriptionPt { get; set; } = "";
    [JsonPropertyName("description_en")] public string? DescriptionEn { get; set; }
    [JsonPropertyName("score")] public int Score { get; set; } = 50;
    [JsonPropertyName("strings")] public Dictionary<string, StringSpec> Strings { get; set; } = new();
    [JsonPropertyName("condition")] public string Condition { get; set; } = "any";
    [JsonPropertyName("filetypes")] public List<string> FileTypes { get; set; } = new() { "any" };
}

public sealed class StringSpec
{
    [JsonPropertyName("text")] public string? Text { get; set; }
    [JsonPropertyName("hex")] public string? Hex { get; set; }
    [JsonPropertyName("regex")] public string? Regex { get; set; }
    [JsonPropertyName("nocase")] public bool NoCase { get; set; }
}

public sealed class CompiledRule
{
    public required RuleDefinition Def { get; init; }
    public required Dictionary<string, Regex> Patterns { get; init; }
    public required ConditionNode Condition { get; init; }

    public string Description => Loc.Pick(Def.DescriptionPt, Def.DescriptionEn);

    public bool AppliesTo(string category) =>
        Def.FileTypes.Contains("any") || Def.FileTypes.Contains(category);

    public bool Matches(string latin1)
    {
        var hits = new Dictionary<string, bool>(Patterns.Count);
        foreach (var (k, rx) in Patterns)
        {
            try { hits[k] = rx.IsMatch(latin1); }
            catch (RegexMatchTimeoutException) { hits[k] = false; }
        }
        return Condition.Eval(hits);
    }
}

public sealed class RuleEngine
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);
    public List<CompiledRule> Rules { get; } = new();

    public static RuleEngine LoadDefault(IEnumerable<string>? extraDirs = null)
    {
        var engine = new RuleEngine();
        var asm = typeof(RuleEngine).Assembly;
        foreach (var res in asm.GetManifestResourceNames().Where(n => n.EndsWith("rules.json", StringComparison.OrdinalIgnoreCase)))
        {
            using var s = asm.GetManifestResourceStream(res)!;
            engine.Load(s);
        }
        foreach (var dir in extraDirs ?? Array.Empty<string>())
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in Directory.EnumerateFiles(dir, "*.json"))
            {
                using var s = File.OpenRead(f);
                engine.Load(s);
            }
        }
        return engine;
    }

    public void Load(Stream json)
    {
        var defs = JsonSerializer.Deserialize<List<RuleDefinition>>(json) ?? new();
        foreach (var d in defs) Rules.Add(Compile(d));
    }

    public static CompiledRule Compile(RuleDefinition d)
    {
        var patterns = new Dictionary<string, Regex>();
        foreach (var (key, spec) in d.Strings)
        {
            var opts = RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.Compiled;
            if (spec.NoCase) opts |= RegexOptions.IgnoreCase;
            string pattern;
            if (spec.Text is not null)
            {
                var ascii = System.Text.RegularExpressions.Regex.Escape(ToLatin1(Encoding.UTF8.GetBytes(spec.Text)));
                var wide = System.Text.RegularExpressions.Regex.Escape(ToLatin1(Encoding.Unicode.GetBytes(spec.Text)));
                pattern = $"{ascii}|{wide}";
            }
            else if (spec.Hex is not null)
                pattern = HexToRegex(spec.Hex);
            else if (spec.Regex is not null)
                pattern = spec.Regex;
            else
                throw new FormatException($"Rule {d.Name}: string '{key}' has no type");
            patterns[key] = new Regex(pattern, opts, Timeout);
        }
        return new CompiledRule
        {
            Def = d,
            Patterns = patterns,
            Condition = ConditionParser.Parse(d.Condition, patterns.Keys.ToHashSet()),
        };
    }

    public IEnumerable<CompiledRule> Scan(string latin1, string category) =>
        Rules.Where(r => r.AppliesTo(category) && r.Matches(latin1));

    public static string ToLatin1(ReadOnlySpan<byte> data) => Encoding.Latin1.GetString(data);

    private static string HexToRegex(string hex)
    {
        var sb = new StringBuilder();
        foreach (var part in hex.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == "??") sb.Append('.');
            else sb.Append("\\x").Append(Convert.ToByte(part, 16).ToString("X2"));
        }
        return sb.ToString();
    }

    public static string CategoryOf(FileKind k) => k switch
    {
        FileKind.Pe => "pe",
        FileKind.Elf => "elf",
        FileKind.Pdf => "pdf",
        FileKind.Lnk => "lnk",
        FileKind.OfficeOle or FileKind.OfficeOpenXml or FileKind.Rtf => "office",
        FileKind.Html => "html",
        FileKind.Script => "script",
        FileKind.Zip or FileKind.Jar or FileKind.Iso => "archive",
        _ => "data",
    };
}


public abstract class ConditionNode
{
    public abstract bool Eval(IReadOnlyDictionary<string, bool> hits);
}

file sealed class CountNode(int min, bool all) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> hits)
    {
        var n = hits.Values.Count(v => v);
        return all ? n == hits.Count : n >= min;
    }
}

file sealed class IdNode(string id) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> hits) => hits.TryGetValue(id, out var v) && v;
}

file sealed class NotNode(ConditionNode inner) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> hits) => !inner.Eval(hits);
}

file sealed class BinNode(ConditionNode l, ConditionNode r, bool and) : ConditionNode
{
    public override bool Eval(IReadOnlyDictionary<string, bool> hits) =>
        and ? l.Eval(hits) && r.Eval(hits) : l.Eval(hits) || r.Eval(hits);
}

public static class ConditionParser
{
    public static ConditionNode Parse(string cond, ISet<string> ids)
    {
        var c = cond.Trim().ToLowerInvariant();
        if (c == "any") return new CountNode(1, false);
        if (c == "all") return new CountNode(0, true);
        if (int.TryParse(c, out var n)) return new CountNode(n, false);
        var tokens = Regex.Matches(c, @"\(|\)|[a-z_][a-z0-9_]*").Select(m => m.Value).ToList();
        int pos = 0;
        var node = ParseOr(tokens, ref pos, ids);
        if (pos != tokens.Count) throw new FormatException($"Invalid condition: '{cond}'");
        return node;
    }

    private static ConditionNode ParseOr(List<string> t, ref int p, ISet<string> ids)
    {
        var left = ParseAnd(t, ref p, ids);
        while (p < t.Count && t[p] == "or") { p++; left = new BinNode(left, ParseAnd(t, ref p, ids), false); }
        return left;
    }

    private static ConditionNode ParseAnd(List<string> t, ref int p, ISet<string> ids)
    {
        var left = ParseUnary(t, ref p, ids);
        while (p < t.Count && t[p] == "and") { p++; left = new BinNode(left, ParseUnary(t, ref p, ids), true); }
        return left;
    }

    private static ConditionNode ParseUnary(List<string> t, ref int p, ISet<string> ids)
    {
        if (p >= t.Count) throw new FormatException("Incomplete condition");
        var tok = t[p++];
        if (tok == "not") return new NotNode(ParseUnary(t, ref p, ids));
        if (tok == "(")
        {
            var inner = ParseOr(t, ref p, ids);
            if (p >= t.Count || t[p++] != ")") throw new FormatException("Missing ')'");
            return inner;
        }
        if (!ids.Contains(tok)) throw new FormatException($"Unknown identifier '{tok}'");
        return new IdNode(tok);
    }
}
