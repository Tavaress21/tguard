using System.IO.Compression;
using System.Text;
using TGuard.Core.Engine;

namespace TGuard.Core.Analyzers;

public static class FileTypeDetector
{
    public static readonly HashSet<string> ExecExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".pif", ".cpl", ".dll", ".sys", ".msi", ".msp", ".ocx" };
    public static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase)
        { ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".bat", ".cmd",
          ".vb", ".sct", ".jar", ".reg", ".py", ".msc", ".scf", ".url", ".appref-ms" };
    public static readonly HashSet<string> ContainerExt = new(StringComparer.OrdinalIgnoreCase)
        { ".iso", ".img", ".vhd", ".vhdx", ".one", ".appx", ".msix", ".appxbundle" };
    public static readonly HashSet<string> DocExt = new(StringComparer.OrdinalIgnoreCase)
        { ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".rtf",
          ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".csv", ".odt", ".ods", ".zip" };
    public static readonly HashSet<string> MacroExt = new(StringComparer.OrdinalIgnoreCase)
        { ".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".potm" };
    public static readonly HashSet<string> HtmlExt = new(StringComparer.OrdinalIgnoreCase)
        { ".html", ".htm", ".shtml", ".svg", ".xhtml", ".mht", ".mhtml" };

    public static FileKind Detect(ReadOnlySpan<byte> d, string name)
    {
        if (d.Length >= 2 && d[0] == 'M' && d[1] == 'Z') return FileKind.Pe;
        if (d.Length >= 4 && d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F') return FileKind.Elf;
        if (StartsWith(d, "%PDF"u8) || d[..Math.Min(1024, d.Length)].IndexOf("%PDF-"u8) >= 0) return FileKind.Pdf;
        if (d.Length >= 8 && d[0] == 0x4C && d[1] == 0 && d[2] == 0 && d[3] == 0 && d[4] == 0x01 && d[5] == 0x14 && d[6] == 0x02 && d[7] == 0x00)
            return FileKind.Lnk;
        if (StartsWith(d, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })) return FileKind.OfficeOle;
        if (StartsWith(d, "{\\rt"u8)) return FileKind.Rtf;
        if (StartsWith(d, "PK\x03\x04"u8)) return DetectZip(d);
        if (d.Length > 0x8006 && d.Slice(0x8001, 5).SequenceEqual("CD001"u8)) return FileKind.Iso;

        var ext = Path.GetExtension(name);
        var head = Encoding.Latin1.GetString(d[..Math.Min(4096, d.Length)]).ToLowerInvariant();
        if (HtmlExt.Contains(ext) || head.Contains("<html") || head.Contains("<!doctype html") || head.Contains("<svg"))
            return FileKind.Html;
        if (ScriptExt.Contains(ext)) return FileKind.Script;
        return FileKind.Data;
    }

    private static FileKind DetectZip(ReadOnlySpan<byte> d)
    {
        try
        {
            using var ms = new MemoryStream(d.ToArray(), false);
            using var z = new ZipArchive(ms, ZipArchiveMode.Read);
            bool contentTypes = false, metaInf = false, cls = false;
            foreach (var e in z.Entries)
            {
                if (e.FullName == "[Content_Types].xml") contentTypes = true;
                if (e.FullName.StartsWith("META-INF/", StringComparison.Ordinal)) metaInf = true;
                if (e.FullName.EndsWith(".class", StringComparison.Ordinal)) cls = true;
            }
            if (contentTypes) return FileKind.OfficeOpenXml;
            if (metaInf && cls) return FileKind.Jar;
        }
        catch (InvalidDataException) { }
        return FileKind.Zip;
    }

    private static bool StartsWith(ReadOnlySpan<byte> d, ReadOnlySpan<byte> prefix) =>
        d.Length >= prefix.Length && d[..prefix.Length].SequenceEqual(prefix);
}
