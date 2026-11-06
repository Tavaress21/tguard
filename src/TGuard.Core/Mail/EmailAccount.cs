namespace TGuard.Core.Mail;

public sealed class EmailAccount
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string Host { get; set; } = "";
    public int Port { get; set; } = 993;
    public bool Ssl { get; set; } = true;
    public string User { get; set; } = "";
    public string Secret { get; set; } = "";
    public string Folder { get; set; } = "INBOX";
    public bool MoveThreats { get; set; } = true;
    public long UidValidity { get; set; }
    public long LastUid { get; set; }
    public DateTimeOffset? LastCheck { get; set; }
    public string? LastError { get; set; }
    public int Scanned { get; set; }
    public int Threats { get; set; }

    public EmailAccount Public() => new()
    {
        Id = Id, Host = Host, Port = Port, Ssl = Ssl, User = User, Folder = Folder, MoveThreats = MoveThreats,
        LastCheck = LastCheck, LastError = LastError, Scanned = Scanned, Threats = Threats,
    };

    public static (string Host, int Port) Preset(string email)
    {
        var domain = email.Contains('@') ? email[(email.IndexOf('@') + 1)..].ToLowerInvariant() : "";
        return domain switch
        {
            "gmail.com" or "googlemail.com" => ("imap.gmail.com", 993),
            "outlook.com" or "outlook.pt" or "hotmail.com" or "hotmail.pt" or "live.com" or "live.com.pt" or "msn.com" => ("outlook.office365.com", 993),
            "yahoo.com" or "yahoo.pt" or "ymail.com" => ("imap.mail.yahoo.com", 993),
            "sapo.pt" => ("imap.sapo.pt", 993),
            "icloud.com" or "me.com" or "mac.com" => ("imap.mail.me.com", 993),
            "gmx.com" or "gmx.net" or "gmx.pt" => ("imap.gmx.com", 993),
            "aol.com" => ("imap.aol.com", 993),
            "zoho.com" => ("imap.zoho.eu", 993),
            _ => (domain.Length > 0 ? "mail." + domain : "", 993),
        };
    }
}
