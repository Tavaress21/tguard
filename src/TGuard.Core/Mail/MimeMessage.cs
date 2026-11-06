using System.Text;
using System.Text.RegularExpressions;

namespace TGuard.Core.Mail;

public sealed class MimeAttachment
{
    public string FileName { get; init; } = "";
    public string ContentType { get; init; } = "";
    public byte[] Data { get; init; } = Array.Empty<byte>();
}

public sealed class MimeMessage
{
    private const int MaxDepth = 12;

    public string Subject { get; private set; } = "";
    public string From { get; private set; } = "";
    public string ReplyTo { get; private set; } = "";
    public string MessageId { get; private set; } = "";
    public string Text { get; private set; } = "";
    public string Html { get; private set; } = "";
    public List<MimeAttachment> Attachments { get; } = new();

    static MimeMessage() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

    public static MimeMessage Parse(byte[] raw)
    {
        var msg = new MimeMessage();
        var (headers, body) = SplitHeaders(raw, 0, raw.Length);
        msg.Subject = DecodeWords(Header(headers, "subject"));
        msg.From = DecodeWords(Header(headers, "from"));
        msg.ReplyTo = DecodeWords(Header(headers, "reply-to"));
        msg.MessageId = Header(headers, "message-id").Trim();
        msg.ReadPart(headers, raw, body, raw.Length, 0);
        return msg;
    }

    public string FromAddress => Address(From);
    public string ReplyToAddress => Address(ReplyTo);

    public static string Address(string header)
    {
        var m = Regex.Match(header, @"<([^<>@\s]+@[^<>\s]+)>");
        if (m.Success) return m.Groups[1].Value.Trim().ToLowerInvariant();
        m = Regex.Match(header, @"[^\s<>""]+@[^\s<>""]+");
        return m.Success ? m.Value.Trim().ToLowerInvariant() : "";
    }

    public string FromDisplayName
    {
        get
        {
            var i = From.IndexOf('<');
            return (i > 0 ? From[..i] : "").Trim().Trim('"').Trim();
        }
    }

    private void ReadPart(List<(string Name, string Value)> headers, byte[] raw, int start, int end, int depth)
    {
        if (depth > MaxDepth) return;
        var contentType = Header(headers, "content-type");
        var mediaType = (contentType.Split(';')[0].Trim().ToLowerInvariant()) is { Length: > 0 } t ? t : "text/plain";
        var disposition = Header(headers, "content-disposition");
        var encoding = Header(headers, "content-transfer-encoding").Trim().ToLowerInvariant();

        if (mediaType.StartsWith("multipart/", StringComparison.Ordinal))
        {
            var boundary = Param(contentType, "boundary");
            if (string.IsNullOrEmpty(boundary)) return;
            foreach (var (s, e) in SplitMultipart(raw, start, end, boundary))
            {
                var (h, b) = SplitHeaders(raw, s, e);
                ReadPart(h, raw, b, e, depth + 1);
            }
            return;
        }

        var data = Decode(raw, start, end, encoding);
        var fileName = DecodeWords(Param(disposition, "filename") ?? Param(contentType, "name") ?? "");
        var isAttachment = disposition.TrimStart().StartsWith("attachment", StringComparison.OrdinalIgnoreCase) || fileName.Length > 0;

        if (mediaType == "message/rfc822")
        {
            Attachments.Add(new MimeAttachment { FileName = fileName.Length > 0 ? fileName : "message.eml", ContentType = mediaType, Data = data });
            var inner = Parse(data);
            Attachments.AddRange(inner.Attachments);
            Text += "\n" + inner.Text;
            Html += "\n" + inner.Html;
            return;
        }

        if (!isAttachment && mediaType == "text/plain") { Text += Charset(contentType).GetString(data) + "\n"; return; }
        if (!isAttachment && mediaType == "text/html") { Html += Charset(contentType).GetString(data) + "\n"; return; }
        if (data.Length == 0) return;
        Attachments.Add(new MimeAttachment
        {
            FileName = fileName.Length > 0 ? fileName : "attachment" + GuessExtension(mediaType),
            ContentType = mediaType,
            Data = data,
        });
    }

    private static string GuessExtension(string mediaType) => mediaType switch
    {
        "text/html" => ".html",
        "text/plain" => ".txt",
        "application/pdf" => ".pdf",
        "application/zip" => ".zip",
        _ => ".bin",
    };

    private static Encoding Charset(string contentType)
    {
        var name = Param(contentType, "charset");
        if (string.IsNullOrEmpty(name)) return Encoding.UTF8;
        try { return Encoding.GetEncoding(name.Trim('"')); }
        catch (ArgumentException) { return Encoding.UTF8; }
    }

    private static byte[] Decode(byte[] raw, int start, int end, string encoding)
    {
        var len = Math.Max(0, end - start);
        if (encoding == "base64")
        {
            var text = Encoding.ASCII.GetString(raw, start, len);
            var clean = new StringBuilder(text.Length);
            foreach (var c in text) if (char.IsLetterOrDigit(c) || c is '+' or '/') clean.Append(c);
            while (clean.Length % 4 != 0) clean.Append('=');
            try { return Convert.FromBase64String(clean.ToString()); }
            catch (FormatException) { return Array.Empty<byte>(); }
        }
        if (encoding == "quoted-printable") return QuotedPrintable(raw, start, end);
        return raw.AsSpan(start, len).ToArray();
    }

    private static byte[] QuotedPrintable(byte[] raw, int start, int end)
    {
        var output = new List<byte>(end - start);
        for (var i = start; i < end; i++)
        {
            var b = raw[i];
            if (b != (byte)'=') { output.Add(b); continue; }
            if (i + 1 < end && raw[i + 1] == '\n') { i += 1; continue; }
            if (i + 2 < end && raw[i + 1] == '\r' && raw[i + 2] == '\n') { i += 2; continue; }
            if (i + 2 < end && Uri.IsHexDigit((char)raw[i + 1]) && Uri.IsHexDigit((char)raw[i + 2]))
            {
                output.Add(Convert.ToByte(Encoding.ASCII.GetString(raw, i + 1, 2), 16));
                i += 2;
                continue;
            }
            output.Add(b);
        }
        return output.ToArray();
    }

    private static (List<(string, string)> Headers, int BodyStart) SplitHeaders(byte[] raw, int start, int end)
    {
        var headers = new List<(string, string)>();
        var i = start;
        string? name = null;
        var value = new StringBuilder();
        while (i < end)
        {
            var lineEnd = Array.IndexOf(raw, (byte)'\n', i, end - i);
            if (lineEnd < 0) lineEnd = end;
            var line = Encoding.Latin1.GetString(raw, i, lineEnd - i).TrimEnd('\r');
            i = Math.Min(end, lineEnd + 1);
            if (line.Length == 0) break;
            if ((line[0] == ' ' || line[0] == '\t') && name is not null) { value.Append(' ').Append(line.Trim()); continue; }
            if (name is not null) headers.Add((name, value.ToString()));
            var colon = line.IndexOf(':');
            if (colon <= 0) { name = null; continue; }
            name = line[..colon].Trim().ToLowerInvariant();
            value.Clear().Append(line[(colon + 1)..].Trim());
        }
        if (name is not null) headers.Add((name, value.ToString()));
        return (headers, i);
    }

    private static IEnumerable<(int Start, int End)> SplitMultipart(byte[] raw, int start, int end, string boundary)
    {
        var marker = Encoding.Latin1.GetBytes("--" + boundary);
        var positions = new List<int>();
        var i = start;
        while (i < end)
        {
            var idx = raw.AsSpan(i, end - i).IndexOf(marker);
            if (idx < 0) break;
            var pos = i + idx;
            if (pos == start || raw[pos - 1] == '\n') positions.Add(pos);
            i = pos + marker.Length;
        }
        for (var k = 0; k < positions.Count; k++)
        {
            var p = positions[k] + marker.Length;
            if (p + 1 < end && raw[p] == '-' && raw[p + 1] == '-') yield break;
            var lineEnd = Array.IndexOf(raw, (byte)'\n', p, end - p);
            if (lineEnd < 0) yield break;
            var partStart = lineEnd + 1;
            var partEnd = k + 1 < positions.Count ? positions[k + 1] : end;
            if (partEnd > partStart && raw[partEnd - 1] == '\n') partEnd--;
            if (partEnd > partStart && raw[partEnd - 1] == '\r') partEnd--;
            if (partEnd >= partStart) yield return (partStart, partEnd);
        }
    }

    private static string Header(List<(string Name, string Value)> headers, string name) =>
        headers.FirstOrDefault(h => h.Name == name).Value ?? "";

    public static string? Param(string header, string name)
    {
        var star = Regex.Match(header, @"(?:^|;)\s*" + Regex.Escape(name) + @"\*(?:0\*?)?\s*=\s*""?([^"";]*)""?", RegexOptions.IgnoreCase);
        if (star.Success)
        {
            var v = star.Groups[1].Value;
            var parts = v.Split('\'', 3);
            if (parts.Length == 3)
            {
                Encoding enc;
                try { enc = string.IsNullOrEmpty(parts[0]) ? Encoding.UTF8 : Encoding.GetEncoding(parts[0]); }
                catch (ArgumentException) { enc = Encoding.UTF8; }
                return enc.GetString(PercentDecode(parts[2]));
            }
            return Uri.UnescapeDataString(v);
        }
        var m = Regex.Match(header, @"(?:^|;)\s*" + Regex.Escape(name) + @"\s*=\s*(?:""((?:[^""\\]|\\.)*)""|([^;\s]+))", RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        return m.Groups[1].Success ? m.Groups[1].Value.Replace("\\\"", "\"") : m.Groups[2].Value;
    }

    private static byte[] PercentDecode(string s)
    {
        var bytes = new List<byte>(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '%' && i + 2 < s.Length && Uri.IsHexDigit(s[i + 1]) && Uri.IsHexDigit(s[i + 2]))
            {
                bytes.Add(Convert.ToByte(s.Substring(i + 1, 2), 16));
                i += 2;
            }
            else bytes.AddRange(Encoding.UTF8.GetBytes(s[i].ToString()));
        }
        return bytes.ToArray();
    }

    private static readonly Regex EncodedWord = new(@"=\?([^?]+)\?([BbQq])\?([^?]*)\?=", RegexOptions.Compiled);

    public static string DecodeWords(string s)
    {
        if (!s.Contains("=?")) return s;
        s = Regex.Replace(s, @"(\?=)\s+(=\?)", "$1$2");
        return EncodedWord.Replace(s, m =>
        {
            Encoding enc;
            try { enc = Encoding.GetEncoding(m.Groups[1].Value.Split('*')[0]); } catch (ArgumentException) { enc = Encoding.UTF8; }
            var text = m.Groups[3].Value;
            try
            {
                if (m.Groups[2].Value is "B" or "b") return enc.GetString(Convert.FromBase64String(text.PadRight((text.Length + 3) / 4 * 4, '=')));
                var bytes = QuotedPrintable(Encoding.ASCII.GetBytes(text.Replace('_', ' ')), 0, text.Length);
                return enc.GetString(bytes);
            }
            catch (FormatException) { return m.Value; }
        });
    }
}
