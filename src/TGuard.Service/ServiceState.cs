using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class ServiceState
{
    private readonly ILogger<ServiceState> _log;
    private readonly Notifier _notifier;

    public TGuardSettings Settings { get; private set; }
    public ScanEngine Engine { get; }
    public Quarantine Quarantine { get; } = new();
    public EventStore Events { get; } = new();
    public AppState State { get; } = AppState.Load();

    public event Action? SettingsChanged;

    public ServiceState(ILogger<ServiceState> log, Notifier notifier)
    {
        _log = log;
        _notifier = notifier;
        Settings = TGuardSettings.Load();
        if (!File.Exists(TGuardPaths.Settings)) Settings.Save();
        Engine = ScanEngine.CreateDefault(Settings);
        _log.LogInformation("TGuard started: {Rules} rules, {Sigs} signatures", Engine.Rules.Rules.Count, Engine.Signatures.Count);
    }

    public void UpdateSettings(TGuardSettings s)
    {
        Settings = s;
        Engine.Settings = s;
        Loc.Language = s.Language;
        s.Save();
        SettingsChanged?.Invoke();
    }

    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

    private static bool IsSystemFile(string path) =>
        WindowsDir.Length > 1 && path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase)
        && !path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase);

    public ThreatInfo? Handle(ScanResult r, string source, bool allowQuarantine = true, string? extraAction = null)
    {
        if (r.Error is not null || r.Verdict == Verdict.Clean) return null;
        var actions = new List<string>();
        if (extraAction is not null) actions.Add(extraAction);
        var blocked = extraAction is not null;
        if (r.Verdict == Verdict.Malicious && Settings.AutoQuarantine && allowQuarantine && IsSystemFile(r.Name))
        {
            actions.Add(Loc.Pick("Não movido: ficheiro do Windows", "Not moved: Windows file"));
        }
        else if (r.Verdict == Verdict.Malicious && Settings.AutoQuarantine && allowQuarantine && File.Exists(r.Name))
        {
            try
            {
                Quarantine.Isolate(r.Name, r.ThreatName ?? r.Headline(), r.AllReasons());
                actions.Add(Loc.Pick("Movido para a quarentena", "Moved to quarantine"));
                blocked = true;
            }
            catch (Exception ex)
            {
                actions.Add(Loc.Pick("Falha na quarentena: ", "Quarantine failed: ") + ex.Message);
                _log.LogWarning(ex, "Failed to quarantine {File}", r.Name);
            }
        }
        var action = string.Join(" · ", actions);
        var info = new ThreatInfo
        {
            Path = r.Name, Name = r.ThreatName ?? r.Headline(), Verdict = r.Verdict.ToString().ToLowerInvariant(),
            Score = r.Score, Reasons = r.AllReasons().ToList(), Action = action,
        };
        Events.Add(new SecurityEvent
        {
            Source = source, Target = r.Name, Verdict = info.Verdict, Score = r.Score,
            Headline = info.Name, Reasons = info.Reasons, Action = action,
        });
        _log.LogWarning("[{Source}] {Verdict} {Score}: {File} - {Name} ({Action})", source, info.Verdict, r.Score, r.Name, info.Name, action);
        _notifier.Publish(new Notification
        {
            Kind = "threat",
            Title = blocked ? Loc.Pick("Ameaça bloqueada", "Threat blocked")
                  : r.Verdict == Verdict.Malicious ? Loc.Pick("Ameaça detetada", "Threat detected")
                  : Loc.Pick("Ficheiro suspeito", "Suspicious file"),
            Message = $"{Path.GetFileName(r.Name)} - {info.Name}",
            Data = System.Text.Json.JsonSerializer.SerializeToNode(info, Protocol.Json),
        });
        return info;
    }
}
