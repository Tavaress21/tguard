using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace TGuard.Core.Mail;

public sealed class ImapException : Exception
{
    public ImapException(string message) : base(message) { }
}

public sealed class ImapResponse
{
    public string Status { get; init; } = "";
    public string Text { get; init; } = "";
    public List<string> Untagged { get; } = new();
    public List<byte[]> Literals { get; } = new();
    public bool Ok => Status == "OK";
}

public sealed class ImapClient : IDisposable
{
    private const int MaxLiteral = 64 * 1024 * 1024;

    private TcpClient? _tcp;
    private Stream? _stream;
    private int _tag;
    private readonly byte[] _buffer = new byte[16 * 1024];
    private int _bufStart, _bufEnd;

    public string Capabilities { get; private set; } = "";

    public async Task ConnectAsync(string host, int port, bool ssl, CancellationToken ct)
    {
        _tcp = new TcpClient { ReceiveTimeout = 60_000, SendTimeout = 60_000 };
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            await _tcp.ConnectAsync(host, port, timeout.Token);
        }
        Stream s = _tcp.GetStream();
        if (ssl)
        {
            var tls = new SslStream(s, false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, ct);
            s = tls;
        }
        _stream = s;
        var greeting = Encoding.UTF8.GetString((await ReadLineAsync(ct)).Line);
        if (!greeting.StartsWith("* OK", StringComparison.OrdinalIgnoreCase) && !greeting.StartsWith("* PREAUTH", StringComparison.OrdinalIgnoreCase))
            throw new ImapException(greeting);
        var cap = await CommandAsync("CAPABILITY", ct);
        Capabilities = string.Join(" ", cap.Untagged.Where(u => u.StartsWith("CAPABILITY", StringComparison.OrdinalIgnoreCase)));
    }

    public async Task LoginAsync(string user, string password, CancellationToken ct)
    {
        ImapResponse r;
        if (Capabilities.Contains("AUTH=PLAIN", StringComparison.OrdinalIgnoreCase) && Capabilities.Contains("SASL-IR", StringComparison.OrdinalIgnoreCase))
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0" + user + "\0" + password));
            r = await CommandAsync("AUTHENTICATE PLAIN " + token, ct);
            if (!r.Ok && r.Status != "NO") r = await CommandAsync($"LOGIN {Quote(user)} {Quote(password)}", ct);
        }
        else r = await CommandAsync($"LOGIN {Quote(user)} {Quote(password)}", ct);
        if (!r.Ok) throw new ImapException(string.IsNullOrWhiteSpace(r.Text) ? "Login failed" : r.Text);
    }

    public async Task<(long UidValidity, long UidNext, int Exists)> SelectAsync(string folder, CancellationToken ct)
    {
        var r = await CommandAsync($"SELECT {Quote(folder)}", ct);
        if (!r.Ok) throw new ImapException(r.Text);
        long validity = 0, next = 0;
        var exists = 0;
        foreach (var u in r.Untagged)
        {
            var m = Regex.Match(u, @"UIDVALIDITY (\d+)", RegexOptions.IgnoreCase);
            if (m.Success) validity = long.Parse(m.Groups[1].Value);
            m = Regex.Match(u, @"UIDNEXT (\d+)", RegexOptions.IgnoreCase);
            if (m.Success) next = long.Parse(m.Groups[1].Value);
            m = Regex.Match(u, @"^(\d+) EXISTS", RegexOptions.IgnoreCase);
            if (m.Success) exists = int.Parse(m.Groups[1].Value);
        }
        return (validity, next, exists);
    }

    public async Task<List<long>> SearchUidsFromAsync(long fromUid, CancellationToken ct)
    {
        var r = await CommandAsync($"UID SEARCH UID {Math.Max(1, fromUid)}:*", ct);
        if (!r.Ok) throw new ImapException(r.Text);
        return r.Untagged.Where(u => u.StartsWith("SEARCH", StringComparison.OrdinalIgnoreCase))
            .SelectMany(u => u[6..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Select(x => long.TryParse(x, out var v) ? v : -1)
            .Where(v => v >= fromUid)
            .Distinct().OrderBy(v => v).ToList();
    }

    public async Task<long> SizeAsync(long uid, CancellationToken ct)
    {
        var r = await CommandAsync($"UID FETCH {uid} (RFC822.SIZE)", ct);
        var m = r.Untagged.Select(u => Regex.Match(u, @"RFC822\.SIZE (\d+)", RegexOptions.IgnoreCase)).FirstOrDefault(x => x.Success);
        return m is not null ? long.Parse(m.Groups[1].Value) : -1;
    }

    public async Task<byte[]?> FetchAsync(long uid, CancellationToken ct)
    {
        var r = await CommandAsync($"UID FETCH {uid} (BODY.PEEK[])", ct);
        if (!r.Ok) throw new ImapException(r.Text);
        return r.Literals.OrderByDescending(l => l.Length).FirstOrDefault();
    }

    public async Task<bool> MoveAsync(long uid, string folder, CancellationToken ct)
    {
        await CommandAsync($"CREATE {Quote(folder)}", ct);
        if (Capabilities.Contains("MOVE", StringComparison.OrdinalIgnoreCase))
        {
            var mv = await CommandAsync($"UID MOVE {uid} {Quote(folder)}", ct);
            if (mv.Ok) return true;
        }
        var cp = await CommandAsync($"UID COPY {uid} {Quote(folder)}", ct);
        if (!cp.Ok) return false;
        var st = await CommandAsync($"UID STORE {uid} +FLAGS.SILENT (\\Deleted)", ct);
        if (st.Ok && Capabilities.Contains("UIDPLUS", StringComparison.OrdinalIgnoreCase)) await CommandAsync($"UID EXPUNGE {uid}", ct);
        return st.Ok;
    }

    public async Task LogoutAsync(CancellationToken ct)
    {
        try { await CommandAsync("LOGOUT", ct); } catch (Exception ex) when (ex is IOException or ImapException or ObjectDisposedException) { }
    }

    public static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    public async Task<ImapResponse> CommandAsync(string command, CancellationToken ct)
    {
        if (_stream is null) throw new InvalidOperationException("not connected");
        var tag = "T" + (++_tag).ToString("D4");
        var bytes = Encoding.UTF8.GetBytes($"{tag} {command}\r\n");
        await _stream.WriteAsync(bytes, ct);
        await _stream.FlushAsync(ct);

        var untagged = new List<string>();
        var literals = new List<byte[]>();
        while (true)
        {
            var (line, lits) = await ReadLineAsync(ct);
            var text = Encoding.UTF8.GetString(line);
            literals.AddRange(lits);
            if (text.StartsWith("* ", StringComparison.Ordinal)) { untagged.Add(text[2..]); continue; }
            if (text.StartsWith("+", StringComparison.Ordinal)) throw new ImapException("unexpected continuation: " + text);
            if (text.StartsWith(tag + " ", StringComparison.Ordinal))
            {
                var rest = text[(tag.Length + 1)..];
                var sp = rest.IndexOf(' ');
                var status = (sp < 0 ? rest : rest[..sp]).ToUpperInvariant();
                var response = new ImapResponse { Status = status, Text = sp < 0 ? "" : rest[(sp + 1)..] };
                response.Untagged.AddRange(untagged);
                response.Literals.AddRange(literals);
                return response;
            }
        }
    }

    private async Task<(byte[] Line, List<byte[]> Literals)> ReadLineAsync(CancellationToken ct)
    {
        var line = new MemoryStream();
        var literals = new List<byte[]>();
        while (true)
        {
            var raw = await ReadRawLineAsync(ct);
            line.Write(raw);
            var m = Regex.Match(Encoding.ASCII.GetString(raw), @"\{(\d+)\+?\}$");
            if (!m.Success) break;
            var size = long.Parse(m.Groups[1].Value);
            if (size > MaxLiteral) throw new ImapException("message too large");
            var lit = new byte[size];
            await ReadExactAsync(lit, ct);
            literals.Add(lit);
        }
        return (line.ToArray(), literals);
    }

    private async Task<byte[]> ReadRawLineAsync(CancellationToken ct)
    {
        var line = new MemoryStream();
        while (true)
        {
            if (_bufStart == _bufEnd) await FillAsync(ct);
            var nl = Array.IndexOf(_buffer, (byte)'\n', _bufStart, _bufEnd - _bufStart);
            if (nl < 0)
            {
                line.Write(_buffer, _bufStart, _bufEnd - _bufStart);
                _bufStart = _bufEnd;
                if (line.Length > 1024 * 1024) throw new ImapException("line too long");
                continue;
            }
            line.Write(_buffer, _bufStart, nl - _bufStart);
            _bufStart = nl + 1;
            var arr = line.ToArray();
            return arr.Length > 0 && arr[^1] == '\r' ? arr[..^1] : arr;
        }
    }

    private async Task ReadExactAsync(byte[] target, CancellationToken ct)
    {
        var done = 0;
        while (done < target.Length)
        {
            if (_bufStart == _bufEnd) await FillAsync(ct);
            var n = Math.Min(target.Length - done, _bufEnd - _bufStart);
            Buffer.BlockCopy(_buffer, _bufStart, target, done, n);
            _bufStart += n;
            done += n;
        }
    }

    private async Task FillAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));
        var n = await _stream!.ReadAsync(_buffer, timeout.Token);
        if (n == 0) throw new IOException("connection closed");
        _bufStart = 0;
        _bufEnd = n;
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _tcp?.Dispose();
    }
}
