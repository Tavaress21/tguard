using System.Text.Json;
using System.Text.Json.Serialization;

namespace TGuard.Core.Storage;

public static class TGuardPaths
{
    public static string Root { get; set; } =
        Environment.GetEnvironmentVariable("TGUARD_HOME") is { Length: > 0 } env
            ? env
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGuard");

    public static string Settings => Path.Combine(Root, "settings.json");
    public static string Signatures => Path.Combine(Root, "signatures.db");
    public static string UrlBlocklist => Path.Combine(Root, "urls.db");
    public static string Allowlist => Path.Combine(Root, "allow.db");
    public static string QuarantineDir => Path.Combine(Root, "Quarantine");
    public static string Events => Path.Combine(Root, "events.jsonl");
    public static string UserRules => Path.Combine(Root, "Rules");
    public static string Logs => Path.Combine(Root, "Logs");

    public static void Ensure()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(QuarantineDir);
        Directory.CreateDirectory(UserRules);
        Directory.CreateDirectory(Logs);
    }
}

public sealed class TGuardSettings
{
    public string Language { get; set; } = "pt";
    public bool StartWithWindows { get; set; } = true;
    public bool Notifications { get; set; } = true;

    public int MaxFileSizeMb { get; set; } = 100;
    public int ArchiveMaxDepth { get; set; } = 3;
    public int ArchiveMaxEntries { get; set; } = 500;
    public int ThresholdSuspicious { get; set; } = 40;
    public int ThresholdMalicious { get; set; } = 80;
    public bool AutoQuarantine { get; set; } = true;

    public bool RealtimeEnabled { get; set; } = true;
    public List<string> WatchFolders { get; set; } = new() { "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "%TEMP%" };
    public List<string> Exclusions { get; set; } = new();

    public bool ScheduledQuickScan { get; set; } = true;
    public int ScheduledQuickScanHour { get; set; } = 13;

    public string UpdateUrl { get; set; } = "https://tguard.luis-tavares.pt/updates/";
    public bool AutoUpdate { get; set; } = true;
    public string AbuseChAuthKey { get; set; } = "";
    public bool AutoInstallUpdates { get; set; } = true;
    public List<string> ExtraUpdateKeys { get; set; } = new();

    public bool ProcessGuardEnabled { get; set; } = true;
    public bool UsbScanEnabled { get; set; } = true;

    public bool CommunitySharing { get; set; } = false;

    public string SiteUrl { get; set; } = "https://luis-tavares.pt/";
    public bool UsageStats { get; set; } = true;

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public static TGuardSettings Load(string? path = null)
    {
        path ??= TGuardPaths.Settings;
        try
        {
            if (File.Exists(path))
                return JsonSerializer.Deserialize<TGuardSettings>(File.ReadAllText(path), Json) ?? new();
        }
        catch (JsonException) { }
        return new();
    }

    public void Save(string? path = null)
    {
        path ??= TGuardPaths.Settings;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, true);
    }

    public static string Expand(string p) => Environment.ExpandEnvironmentVariables(p);
}
