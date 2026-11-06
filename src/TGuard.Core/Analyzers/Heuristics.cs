using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using TGuard.Core.Engine;

namespace TGuard.Core.Analyzers;

public static class Heuristics
{
    private const char Rtlo = '‮';

    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double e = 0, n = data.Length;
        foreach (var c in counts)
            if (c > 0) { var p = c / n; e -= p * Math.Log2(p); }
        return e;
    }

    public static IEnumerable<Finding> Name(string name, FileKind kind, bool fromEmail)
    {
        var baseName = Path.GetFileName(name);
        var ext = Path.GetExtension(baseName);
        if (baseName.Contains(Rtlo)) yield return new(60, Loc.T("name.rtlo"));

        var parts = baseName.ToLowerInvariant().Split('.');
        if (parts.Length >= 3 && FileTypeDetector.DocExt.Contains("." + parts[^2])
            && (FileTypeDetector.ExecExt.Contains(ext) || FileTypeDetector.ScriptExt.Contains(ext)))
            yield return new(50, Loc.T("name.double", $".{parts[^2]}{ext}"));
        if (Regex.IsMatch(baseName, @"\s{5,}\.\w+$")) yield return new(40, Loc.T("name.spaces"));
        if (kind == FileKind.Pe && FileTypeDetector.DocExt.Contains(ext))
            yield return new(70, Loc.T("name.pe_as_doc", ext));
        if (kind == FileKind.Html && ext is ".pdf" or ".doc" or ".docx" or ".xls" or ".xlsx")
            yield return new(40, Loc.T("name.html_as_doc", ext));

        if (!fromEmail) yield break;
        if (FileTypeDetector.ExecExt.Contains(ext) || kind == FileKind.Pe) yield return new(45, Loc.T("email.exe"));
        else if (FileTypeDetector.ScriptExt.Contains(ext)) yield return new(45, Loc.T("email.script", ext));
        else if (FileTypeDetector.ContainerExt.Contains(ext) || kind == FileKind.Iso) yield return new(35, Loc.T("email.container", ext));
        else if (kind == FileKind.Lnk || ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)) yield return new(50, Loc.T("email.lnk"));
        else if (FileTypeDetector.MacroExt.Contains(ext)) yield return new(20, Loc.T("email.macro"));
        else if (FileTypeDetector.HtmlExt.Contains(ext)) yield return new(15, Loc.T("email.html"));
    }

    private static readonly Dictionary<string, string> DangerousImports = new(StringComparer.OrdinalIgnoreCase)
    {
        ["VirtualAllocEx"] = "inject", ["WriteProcessMemory"] = "inject", ["CreateRemoteThread"] = "inject",
        ["NtUnmapViewOfSection"] = "inject", ["QueueUserAPC"] = "inject", ["SetThreadContext"] = "inject",
        ["SetWindowsHookExA"] = "spy", ["SetWindowsHookExW"] = "spy", ["GetAsyncKeyState"] = "spy",
        ["CryptEncrypt"] = "crypto", ["BCryptEncrypt"] = "crypto",
        ["URLDownloadToFileA"] = "net", ["URLDownloadToFileW"] = "net",
        ["IsDebuggerPresent"] = "anti", ["CheckRemoteDebuggerPresent"] = "anti",
        ["AdjustTokenPrivileges"] = "priv",
    };

    public static IEnumerable<Finding> Pe(byte[] data)
    {
        var ent = Entropy(data);
        if (ent > 7.2) yield return new(15, Loc.T("pe.entropy", ent));
        var head = data.AsSpan(0, Math.Min(4096, data.Length));
        if (head.IndexOf("UPX0"u8) >= 0 || head.IndexOf("UPX!"u8) >= 0) yield return new(10, Loc.T("pe.upx"));

        var pe = PeFile.TryParse(data, out _);
        if (pe is null) { yield return new(25, Loc.T("pe.malformed")); yield break; }

        var names = pe.Imports.Select(i => i.Function).Where(n => n.Length > 0).ToHashSet();
        if (!pe.IsDotNet && !pe.IsDll && names.Count < 5)
            yield return new(20, Loc.T("pe.fewimports", names.Count));

        var wx = pe.Sections.FirstOrDefault(s => s.Executable && s.Writable);
        if (wx is not null) yield return new(20, Loc.T("pe.wx", wx.Name));
        if (pe.Sections.Any(s => s.RawSize == 0 && s.VirtualSize > 0x100000 && s.Executable))
            yield return new(15, Loc.T("pe.unpack"));
        if (pe.SecurityDirectory.Rva == 0) yield return new(10, Loc.T("pe.unsigned"));
        if (!pe.IsDotNet && pe.TimeDateStamp > DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds() && pe.TimeDateStamp < 0xF0000000)
            yield return new(10, Loc.T("pe.future"));
        if (pe.OverlaySize > 2_000_000 && pe.SecurityDirectory.Rva == 0)
            yield return new(10, Loc.T("pe.overlay", pe.OverlaySize / 1048576.0));

        var cats = names.Where(DangerousImports.ContainsKey).GroupBy(n => DangerousImports[n]).ToDictionary(g => g.Key, g => g.ToList());
        if (cats.TryGetValue("inject", out var inj) && inj.Count >= 3)
            yield return new(35, Loc.T("pe.imports", string.Join(", ", inj.Take(4))));
        if (cats.TryGetValue("spy", out var spy) && spy.Count >= 2)
            yield return new(25, Loc.T("pe.imports", string.Join(", ", spy)));
    }

    public static IEnumerable<Finding> Office(byte[] data, FileKind kind)
    {
        var list = new List<Finding>();
        if (kind == FileKind.OfficeOpenXml)
        {
            try
            {
                using var z = new ZipArchive(new MemoryStream(data, false), ZipArchiveMode.Read);
                if (z.Entries.Any(e => e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)))
                    list.Add(new(25, Loc.T("office.vba")));
                foreach (var e in z.Entries.Where(e => e.FullName.EndsWith(".rels", StringComparison.Ordinal) && e.Length < 1_000_000))
                {
                    using var sr = new StreamReader(e.Open());
                    var rel = sr.ReadToEnd();
                    if (rel.Contains("TargetMode=\"External\"") &&
                        Regex.IsMatch(rel, @"Type=""[^""]*(attachedTemplate|oleObject|frame)""[^>]*Target=""(https?|\\\\|file)", RegexOptions.IgnoreCase)
                        || Regex.IsMatch(rel, @"Target=""(https?|\\\\|file)[^""]*""[^>]*Type=""[^""]*(attachedTemplate|oleObject|frame)""", RegexOptions.IgnoreCase))
                    {
                        list.Add(new(45, Loc.T("office.template")));
                        break;
                    }
                }
                if (z.Entries.Any(e => e.FullName.Contains("activeX", StringComparison.OrdinalIgnoreCase)))
                    list.Add(new(15, Loc.T("office.activex")));
                if (z.Entries.Any(e => e.FullName.Contains("embeddings", StringComparison.OrdinalIgnoreCase) && e.FullName.EndsWith(".bin")))
                    list.Add(new(20, Loc.T("office.ole")));
            }
            catch (InvalidDataException) { }
        }
        else if (kind == FileKind.OfficeOle)
        {
            var s = data.AsSpan();
            if (s.IndexOf("_VBA_PROJECT"u8) >= 0 || s.IndexOf("V\0B\0A\0"u8) >= 0 || s.IndexOf("Attribute VB_"u8) >= 0
                || ExtractVbaSource(data).Length > 0)
                list.Add(new(25, Loc.T("office.vba")));
            if (s.IndexOf("Equation.3"u8) >= 0 || s.IndexOf("EQNEDT32"u8) >= 0)
                list.Add(new(50, Loc.T("office.equation")));
        }
        else if (kind == FileKind.Rtf)
        {
            var t = Encoding.Latin1.GetString(data);
            if (Regex.IsMatch(t, @"\\obj(data|update|emb)", RegexOptions.IgnoreCase)) list.Add(new(30, Loc.T("office.rtfobj")));
            if (Regex.IsMatch(t, @"equation\.?3", RegexOptions.IgnoreCase)) list.Add(new(50, Loc.T("office.equation")));
        }
        return list;
    }

    public static byte[] OvbaDecompress(ReadOnlySpan<byte> buf, int maxOut = 2_000_000)
    {
        if (buf.IsEmpty || buf[0] != 1) throw new FormatException("bad signature byte");
        var output = new List<byte>(4096);
        int pos = 1;
        while (pos + 2 <= buf.Length && output.Count < maxOut)
        {
            int header = buf[pos] | (buf[pos + 1] << 8);
            int chunkEnd = Math.Min(pos + (header & 0x0FFF) + 3, buf.Length);
            pos += 2;
            int start = output.Count;
            if ((header & 0x8000) == 0)
            {
                var len = Math.Min(4096, buf.Length - pos);
                for (int i = 0; i < len; i++) output.Add(buf[pos + i]);
                pos += 4096;
                continue;
            }
            while (pos < chunkEnd)
            {
                byte flags = buf[pos++];
                for (int bit = 0; bit < 8 && pos < chunkEnd; bit++)
                {
                    if ((flags & (1 << bit)) == 0) { output.Add(buf[pos++]); continue; }
                    if (pos + 1 >= buf.Length) throw new FormatException("truncated token");
                    int token = buf[pos] | (buf[pos + 1] << 8);
                    pos += 2;
                    int d = output.Count - start;
                    int bitCount = Math.Max(BitLength(d - 1), 4);
                    int lenMask = 0xFFFF >> bitCount;
                    int length = (token & lenMask) + 3;
                    int offset = (token >> (16 - bitCount)) + 1;
                    if (offset > output.Count) throw new FormatException("bad offset");
                    for (int i = 0; i < length; i++) output.Add(output[^offset]);
                }
            }
        }
        return output.ToArray();
    }

    public static string ExtractWideStrings(ReadOnlySpan<byte> d, int minLen = 4)
    {
        var sb = new StringBuilder();
        var cur = new StringBuilder();
        for (int i = 0; i + 1 < d.Length; i += 2)
        {
            byte lo = d[i], hi = d[i + 1];
            if (hi == 0 && lo >= 0x20 && lo < 0x7F) { cur.Append((char)lo); continue; }
            if (cur.Length >= minLen) sb.Append(cur).Append('\n');
            cur.Clear();
            if (hi != 0 && i + 2 < d.Length && d[i + 2] == 0) i--;
        }
        if (cur.Length >= minLen) sb.Append(cur);
        return sb.ToString();
    }

    private static int BitLength(int v) => v <= 0 ? 0 : 32 - System.Numerics.BitOperations.LeadingZeroCount((uint)v);

    public static byte[] ExtractVbaSource(byte[] data)
    {
        var result = new List<byte>();
        var marker = "\0Attribut"u8;
        var span = data.AsSpan();
        int idx = 0;
        while (true)
        {
            var rel = span[idx..].IndexOf(marker);
            if (rel < 0) break;
            int m = idx + rel;
            idx = m + 1;
            if (m + marker.Length < data.Length && data[m + marker.Length] == (byte)'e') continue;
            int start = m - 3;
            if (start < 0 || data[start] != 1) continue;
            try
            {
                var src = OvbaDecompress(span.Slice(start, Math.Min(500_000, data.Length - start)));
                if (src.AsSpan().IndexOf("Attribute VB_"u8) >= 0) { result.AddRange(src); result.Add((byte)'\n'); }
            }
            catch (FormatException) { }
        }
        return result.ToArray();
    }

    public static IEnumerable<Finding> Pdf(byte[] data)
    {
        var t = Encoding.Latin1.GetString(data);
        if (t.Contains("/EmbeddedFile")) yield return new(20, Loc.T("pdf.embedded"));
        if (Regex.IsMatch(t, @"/Launch\b")) yield return new(30, Loc.T("pdf.launch"));
        if (Regex.IsMatch(t, @"/(JavaScript|JS)\b")) yield return new(15, Loc.T("pdf.js"));
        if (data.Length < 50_000 && Regex.IsMatch(t, @"/URI\s*\(") && Regex.Matches(t, @"/Type\s*/Page\b").Count <= 2)
            yield return new(10, Loc.T("pdf.lure"));
    }

    public static IEnumerable<Finding> Script(byte[] data)
    {
        var len = Math.Min(200_000, data.Length);
        var t = Encoding.Latin1.GetString(data, 0, len);
        if (Regex.IsMatch(t, @"[A-Za-z0-9+/]{400,}={0,2}")) yield return new(15, Loc.T("script.b64"));
        if (len > 2000 && SymbolRatio(t) > 0.35) yield return new(15, Loc.T("script.symbols"));
        if (Regex.IsMatch(t, @"(['""][^'""]{1,3}['""]\s*\+\s*){15,}")) yield return new(20, Loc.T("script.concat"));
    }

    private static double SymbolRatio(string t)
    {
        int odd = 0;
        foreach (var c in t)
            if (!(char.IsAsciiLetterOrDigit(c) || c is ' ' or '\r' or '\n' or '\t')) odd++;
        return odd / (double)t.Length;
    }
}
