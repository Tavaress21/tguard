using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;
using TGuard.Core.Mail;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class EmailGuard : BackgroundService
{
    private const string QuarantineFolder = "TGuard Quarentena";
    private const int MaxMessageBytes = 30 * 1024 * 1024;
    private const int MaxPerRound = 40;
    private const int FirstRunBacklog = 25;
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(3);
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly ServiceState _state;
    private readonly Notifier _notifier;
    private readonly ILogger<EmailGuard> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _fileLock = new();
    private readonly SemaphoreSlim _wake = new(0);

    public EmailGuard(ServiceState state, Notifier notifier, ILogger<EmailGuard> log)
    {
        _state = state;
        _notifier = notifier;
        _log = log;
    }

    public bool Active => _state.Settings.EmailProtection && Load().Count > 0;

    public List<EmailAccount> Accounts() => Load().Select(a => a.Public()).ToList();

    public void CheckNow() => _wake.Release();

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(45), ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            if (_state.Settings.EmailProtection) await CheckAllAsync(ct);
            try { await _wake.WaitAsync(Interval, ct); } catch (OperationCanceledException) { return; }
        }
    }

    public async Task<EmailAccount> AddAsync(string user, string password, string? host, int port, bool ssl, bool moveThreats, CancellationToken ct)
    {
        user = user.Trim();
        if (user.Length == 0 || password.Length == 0) throw new ArgumentException(Loc.Pick("Indica o email e a palavra-passe.", "Enter the email and password."));
        var preset = EmailAccount.Preset(user);
        var account = new EmailAccount
        {
            User = user,
            Host = string.IsNullOrWhiteSpace(host) ? preset.Host : host.Trim(),
            Port = port > 0 ? port : preset.Port,
            Ssl = ssl,
            MoveThreats = moveThreats,
            Secret = Protect(password),
        };
        if (account.Host.Length == 0) throw new ArgumentException(Loc.Pick("Indica o servidor IMAP.", "Enter the IMAP server."));

        using (var imap = new ImapClient())
        {
            try
            {
                await imap.ConnectAsync(account.Host, account.Port, account.Ssl, ct);
                await imap.LoginAsync(account.User, password, ct);
                var (validity, next, _) = await imap.SelectAsync(account.Folder, ct);
                account.UidValidity = validity;
                account.LastUid = Math.Max(0, next - 1 - FirstRunBacklog);
                await imap.LogoutAsync(ct);
            }
            catch (Exception ex) when (ex is ImapException or IOException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException or OperationCanceledException)
            {
                throw new InvalidOperationException(LoginHelp(account, ex.Message));
            }
        }

        lock (_fileLock)
        {
            var all = Load();
            all.RemoveAll(a => a.User.Equals(account.User, StringComparison.OrdinalIgnoreCase) && a.Host.Equals(account.Host, StringComparison.OrdinalIgnoreCase));
            all.Add(account);
            Save(all);
        }
        CheckNow();
        return account.Public();
    }

    public void Remove(string id)
    {
        lock (_fileLock)
        {
            var all = Load();
            all.RemoveAll(a => a.Id == id);
            Save(all);
        }
    }

    private static string LoginHelp(EmailAccount a, string error)
    {
        var host = a.Host.ToLowerInvariant();
        if (host.Contains("gmail"))
            return Loc.Pick("O Gmail recusou o login. Usa uma palavra-passe de app (myaccount.google.com/apppasswords), não a palavra-passe normal.",
                            "Gmail refused the login. Use an app password (myaccount.google.com/apppasswords), not your normal password.") + $" ({error})";
        if (host.Contains("office365") || host.Contains("outlook"))
            return Loc.Pick("A Microsoft já não permite IMAP com palavra-passe nas contas Outlook/Hotmail. Os anexos abertos no Outlook do PC continuam protegidos.",
                            "Microsoft no longer allows IMAP with a password on Outlook/Hotmail accounts. Attachments opened in desktop Outlook are still protected.") + $" ({error})";
        if (host.Contains("yahoo") || host.Contains("icloud") || host.Contains("me.com"))
            return Loc.Pick("Este serviço exige uma palavra-passe de app para IMAP.", "This provider requires an app password for IMAP.") + $" ({error})";
        return Loc.Pick("Não foi possível entrar na conta: ", "Could not sign in: ") + error;
    }

    private async Task CheckAllAsync(CancellationToken ct)
    {
        if (!await _gate.WaitAsync(0, ct)) return;
        try
        {
            foreach (var account in Load())
            {
                if (ct.IsCancellationRequested) return;
                try { await CheckAsync(account, ct); account.LastError = null; }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
                catch (Exception ex)
                {
                    account.LastError = ex.Message;
                    _log.LogInformation("Email check for {User} failed: {Error}", account.User, ex.Message);
                }
                account.LastCheck = DateTimeOffset.Now;
                lock (_fileLock)
                {
                    var all = Load();
                    var i = all.FindIndex(a => a.Id == account.Id);
                    if (i < 0) continue;
                    all[i].LastUid = account.LastUid;
                    all[i].UidValidity = account.UidValidity;
                    all[i].LastCheck = account.LastCheck;
                    all[i].LastError = account.LastError;
                    all[i].Scanned = account.Scanned;
                    all[i].Threats = account.Threats;
                    Save(all);
                }
            }
        }
        finally { _gate.Release(); }
    }

    private async Task CheckAsync(EmailAccount account, CancellationToken ct)
    {
        using var imap = new ImapClient();
        await imap.ConnectAsync(account.Host, account.Port, account.Ssl, ct);
        await imap.LoginAsync(account.User, Unprotect(account.Secret), ct);
        var (validity, next, _) = await imap.SelectAsync(account.Folder, ct);
        if (validity != account.UidValidity)
        {
            account.UidValidity = validity;
            account.LastUid = Math.Max(0, next - 1 - FirstRunBacklog);
        }
        var uids = await imap.SearchUidsFromAsync(account.LastUid + 1, ct);
        foreach (var uid in uids.Take(MaxPerRound))
        {
            ct.ThrowIfCancellationRequested();
            var size = await imap.SizeAsync(uid, ct);
            if (size is > 0 and <= MaxMessageBytes && await imap.FetchAsync(uid, ct) is byte[] raw)
            {
                account.Scanned++;
                if (await Task.Run(() => Inspect(account, raw, ct), ct) is { } verdict)
                {
                    account.Threats++;
                    if (verdict == Verdict.Malicious && account.MoveThreats)
                    {
                        var moved = await imap.MoveAsync(uid, QuarantineFolder, ct);
                        _log.LogInformation("Email {Uid} of {User} moved to {Folder}: {Moved}", uid, account.User, QuarantineFolder, moved);
                    }
                }
            }
            account.LastUid = uid;
        }
        await imap.LogoutAsync(ct);
    }

    private Verdict? Inspect(EmailAccount account, byte[] raw, CancellationToken ct)
    {
        MimeMessage msg;
        try { msg = MimeMessage.Parse(raw); }
        catch (Exception ex) { _log.LogDebug(ex, "Could not parse an email of {User}", account.User); return null; }

        var found = EmailScanner.Scan(_state.Engine, msg, ct);
        if (found.Verdict == Verdict.Clean) return null;

        var actions = new List<string>();
        if (found.Verdict == Verdict.Malicious)
        {
            foreach (var (att, r) in found.BadAttachments.Where(b => b.Result.Verdict == Verdict.Malicious))
            {
                try
                {
                    _state.Quarantine.Store(att.Data, $"email:{account.User}/{att.FileName}", r.ThreatName ?? r.Headline(), r.AllReasons());
                    actions.Add(Loc.Pick($"Cópia de {att.FileName} na quarentena", $"Copy of {att.FileName} quarantined"));
                }
                catch (Exception ex) { _log.LogWarning(ex, "Could not quarantine an email attachment"); }
            }
            if (account.MoveThreats) actions.Add(Loc.Pick($"Movido para a pasta \"{QuarantineFolder}\"", $"Moved to the \"{QuarantineFolder}\" folder"));
        }

        var subject = string.IsNullOrWhiteSpace(msg.Subject) ? Loc.Pick("(sem assunto)", "(no subject)") : msg.Subject;
        var result = new ScanResult
        {
            Name = $"{account.User}: {Truncate(subject, 120)} — {Truncate(msg.FromAddress, 80)}",
            Score = found.Score,
            Verdict = found.Verdict,
            ThreatName = found.ThreatName,
        };
        result.Findings.AddRange(found.Findings);
        _state.Handle(result, "email", allowQuarantine: false, extraAction: actions.Count > 0 ? string.Join(" · ", actions) : null);
        _notifier.Publish(new Notification
        {
            Kind = "email",
            Title = found.Verdict == Verdict.Malicious ? Loc.Pick("Email perigoso bloqueado", "Dangerous email blocked") : Loc.Pick("Email suspeito", "Suspicious email"),
            Message = $"{Truncate(subject, 80)} · {msg.FromAddress}",
        });
        return found.Verdict;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    private List<EmailAccount> Load()
    {
        lock (_fileLock)
        {
            try
            {
                if (File.Exists(TGuardPaths.EmailAccounts))
                    return JsonSerializer.Deserialize<List<EmailAccount>>(File.ReadAllText(TGuardPaths.EmailAccounts)) ?? new();
            }
            catch (Exception ex) when (ex is JsonException or IOException) { _log.LogWarning(ex, "Could not read email accounts"); }
            return new();
        }
    }

    private void Save(List<EmailAccount> accounts)
    {
        lock (_fileLock)
        {
            var tmp = TGuardPaths.EmailAccounts + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(accounts, Json));
            File.Move(tmp, TGuardPaths.EmailAccounts, true);
        }
    }

    private static string Protect(string secret) => Convert.ToBase64String(Dpapi.Protect(Encoding.UTF8.GetBytes(secret)));

    private static string Unprotect(string secret) => Encoding.UTF8.GetString(Dpapi.Unprotect(Convert.FromBase64String(secret)));

    private static class Dpapi
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        private static readonly byte[] Entropy = "TGuard.EmailAccounts.v1"u8.ToArray();

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(ref DATA_BLOB data, string? description, ref DATA_BLOB entropy, IntPtr reserved, IntPtr prompt, int flags, out DATA_BLOB output);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(ref DATA_BLOB data, IntPtr description, ref DATA_BLOB entropy, IntPtr reserved, IntPtr prompt, int flags, out DATA_BLOB output);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr mem);

        public static byte[] Protect(byte[] plain) => Run(plain, true);

        public static byte[] Unprotect(byte[] cipher) => Run(cipher, false);

        private static byte[] Run(byte[] input, bool protect)
        {
            var inHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
            var entHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
            try
            {
                var data = new DATA_BLOB { cbData = input.Length, pbData = inHandle.AddrOfPinnedObject() };
                var entropy = new DATA_BLOB { cbData = Entropy.Length, pbData = entHandle.AddrOfPinnedObject() };
                var ok = protect
                    ? CryptProtectData(ref data, null, ref entropy, IntPtr.Zero, IntPtr.Zero, 0x1, out var output)
                    : CryptUnprotectData(ref data, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, 0x1, out output);
                if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                try
                {
                    var result = new byte[output.cbData];
                    Marshal.Copy(output.pbData, result, 0, output.cbData);
                    return result;
                }
                finally { LocalFree(output.pbData); }
            }
            finally
            {
                inHandle.Free();
                entHandle.Free();
            }
        }
    }
}
