namespace TGuard.Core.Online;

public sealed class SyncRequest
{
    public string InstallId { get; set; } = "";
    public string? Token { get; set; }
    public string Version { get; set; } = SiteClient.Version;
    public string Os { get; set; } = SiteClient.Os;
    public int Signatures { get; set; }
    public DeviceStatus Status { get; set; } = new();
    public List<SyncEvent> Events { get; set; } = new();
    public List<CommandResult> Results { get; set; } = new();
}

public sealed class DeviceStatus
{
    public bool Realtime { get; set; }
    public bool ProcessGuard { get; set; }
    public bool Usb { get; set; }
    public bool Ransomware { get; set; }
    public bool Email { get; set; }
    public int EmailAccounts { get; set; }
    public int Quarantine { get; set; }
    public int Threats30d { get; set; }
    public DateTimeOffset? LastScan { get; set; }
    public string? LastScanType { get; set; }
    public DateTimeOffset? LastUpdate { get; set; }
    public int Rules { get; set; }
    public int BadUrls { get; set; }
    public bool ScanRunning { get; set; }
    public int ScanFiles { get; set; }
}

public sealed class SyncEvent
{
    public DateTimeOffset Date { get; set; }
    public string Source { get; set; } = "";
    public string Verdict { get; set; } = "";
    public string Name { get; set; } = "";
    public int Score { get; set; }
    public string? File { get; set; }
    public string? Action { get; set; }
}

public sealed class CommandResult
{
    public long Id { get; set; }
    public bool Ok { get; set; }
    public string Message { get; set; } = "";
}

public sealed class RemoteCommand
{
    public long Id { get; set; }
    public string Type { get; set; } = "";
}

public sealed class SyncResponse
{
    public string? AccountName { get; set; }
    public bool AccountRevoked { get; set; }
    public List<RemoteCommand> Commands { get; } = new();
}

public sealed class LinkStart
{
    public string Code { get; set; } = "";
    public string Secret { get; set; } = "";
    public string Url { get; set; } = "";
    public int ExpiresIn { get; set; }
}

public sealed class LinkPoll
{
    public bool Linked { get; set; }
    public bool Expired { get; set; }
    public string? Token { get; set; }
    public LinkAccount? Account { get; set; }
}

public sealed class LinkAccount
{
    public string? Name { get; set; }
    public string? Email { get; set; }
}

public sealed class ReportRequest
{
    public string Type { get; set; } = "false_positive";
    public string? Value { get; set; }
    public string? FileName { get; set; }
    public string? Detection { get; set; }
    public string? Details { get; set; }
}

public sealed class AccountStatus
{
    public bool Linked { get; set; }
    public string? Name { get; set; }
    public string? Email { get; set; }
    public bool UsageStats { get; set; }
}
