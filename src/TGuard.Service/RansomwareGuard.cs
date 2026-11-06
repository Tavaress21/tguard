using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using TGuard.Core;
using TGuard.Core.Engine;
using TGuard.Core.Ipc;
using TGuard.Core.Security;
using TGuard.Core.Storage;

namespace TGuard.Service;

public sealed class RansomwareGuard : BackgroundService
{
    private static readonly string[] ProtectedFolders =
        { "%USERPROFILE%\\Documents", "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Pictures", "%USERPROFILE%\\Videos", "%USERPROFILE%\\Music" };

    private static readonly string[] TrustedRoots =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
    };

    private readonly ServiceState _state;
    private readonly Notifier _notifier;
    private readonly ILogger<RansomwareGuard> _log;
    private readonly RansomwareDetector _detector = new();
    private readonly List<FileSystemWatcher> _watchers = new();
    private List<string> _folders = new();
    private DateTime _lastIncident = DateTime.MinValue;

    public bool Active { get; private set; }
    public int ProtectedFolderCount => _folders.Count;

    public RansomwareGuard(ServiceState state, Notifier notifier, ILogger<RansomwareGuard> log)
    {
        _state = state;
        _notifier = notifier;
        _log = log;
        _state.SettingsChanged += Rebuild;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        Rebuild();
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromMinutes(10), ct); } catch (OperationCanceledException) { break; }
            Rebuild();
        }
        lock (_watchers) foreach (var w in _watchers) w.Dispose();
    }

    private void Rebuild()
    {
        lock (_watchers)
        {
            var enabled = _state.Settings.RansomwareProtection;
            var wanted = enabled ? UserFolders.Resolve(ProtectedFolders) : new List<string>();
            foreach (var dir in wanted) EnsureCanaries(dir);
            if (wanted.Count == _folders.Count && wanted.All(f => _folders.Contains(f, StringComparer.OrdinalIgnoreCase)) && _watchers.Count == wanted.Count)
                return;
            foreach (var w in _watchers) w.Dispose();
            _watchers.Clear();
            _folders = wanted;
            if (!enabled)
            {
                Active = false;
                RemoveCanaries();
                return;
            }
            foreach (var dir in wanted)
            {
                try
                {
                    var w = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        InternalBufferSize = 64 * 1024,
                    };
                    w.Created += (_, e) => OnChange(e.FullPath, ChangeKind.Created, null);
                    w.Changed += (_, e) => OnChange(e.FullPath, ChangeKind.Changed, null);
                    w.Deleted += (_, e) => OnChange(e.FullPath, ChangeKind.Deleted, null);
                    w.Renamed += (_, e) => OnChange(e.FullPath, ChangeKind.Renamed, e.OldFullPath);
                    w.EnableRaisingEvents = true;
                    _watchers.Add(w);
                }
                catch (Exception ex) { _log.LogWarning(ex, "Could not protect {Dir}", dir); }
            }
            Active = _watchers.Count > 0;
            _log.LogInformation("Ransomware protection watching {Count} folders", _watchers.Count);
        }
    }

    private void EnsureCanaries(string dir)
    {
        foreach (var ext in RansomwareDetector.CanaryExtensions)
        {
            var path = Path.Combine(dir, RansomwareDetector.CanaryPrefix + ext);
            try
            {
                byte[] content;
                if (File.Exists(path)) content = File.ReadAllBytes(path);
                else
                {
                    content = RansomwareDetector.CanaryContent(ext);
                    File.WriteAllBytes(path, content);
                }
                File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
                _detector.Register(path, content);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _log.LogDebug(ex, "Could not place canary in {Dir}", dir);
            }
        }
    }

    private void RemoveCanaries()
    {
        foreach (var path in _detector.Canaries)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            _detector.Forget(path);
        }
    }

    private void OnChange(string path, ChangeKind kind, string? oldPath)
    {
        string? reason;
        try { reason = _detector.OnChange(path, kind, oldPath, DateTime.UtcNow, ReadSafe); }
        catch (Exception ex) { _log.LogDebug(ex, "Ransomware check failed for {Path}", path); return; }
        if (reason is null) return;
        _ = Task.Run(() => Respond(reason, oldPath ?? path));
    }

    private static byte[]? ReadSafe(string path)
    {
        for (var i = 0; i < 5; i++)
        {
            try { return File.ReadAllBytes(path); }
            catch (IOException) { Thread.Sleep(100); }
            catch (UnauthorizedAccessException) { return null; }
        }
        return null;
    }

    private void Respond(string reason, string trigger)
    {
        lock (_watchers)
        {
            if ((DateTime.UtcNow - _lastIncident).TotalSeconds < 5) return;
            _lastIncident = DateTime.UtcNow;
        }
        _log.LogWarning("Ransomware behaviour: {Reason}", reason);

        var suspects = new Dictionary<int, string>();
        foreach (var pid in RestartManager.ProcessesUsing(trigger))
            if (pid != Environment.ProcessId && ImagePathOf(pid) is string exe && !IsCritical(exe)) suspects[pid] = exe;
        foreach (var (pid, exe) in RecentSuspects(TimeSpan.FromMinutes(30))) suspects.TryAdd(pid, exe);

        var stopped = new List<string>();
        foreach (var (pid, exe) in suspects)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                p.Kill(entireProcessTree: true);
                p.WaitForExit(3000);
            }
            catch (ArgumentException) { }
            catch (Exception ex) { _log.LogWarning(ex, "Could not stop {Exe}", exe); continue; }
            stopped.Add(Path.GetFileName(exe));
            var isolate = !CommandLineAnalyzer.ScriptHosts.Contains(Path.GetFileName(exe)) && !IsTrustedImage(exe);
            var r = new ScanResult { Name = exe, Score = 100, Verdict = Verdict.Malicious, ThreatName = "TGuard.Ransomware.Behavior" };
            r.Findings.Add(new Finding(100, reason, "ransomware"));
            _state.Handle(r, "ransomware", allowQuarantine: isolate, extraAction: Loc.Pick("Processo terminado", "Process terminated"));
        }

        if (stopped.Count == 0)
        {
            var r = new ScanResult { Name = trigger, Score = 80, Verdict = Verdict.Suspicious, ThreatName = "TGuard.Ransomware.Behavior" };
            r.Findings.Add(new Finding(80, reason, "ransomware"));
            _state.Handle(r, "ransomware", allowQuarantine: false);
        }

        _notifier.Publish(new Notification
        {
            Kind = "ransomware",
            Title = stopped.Count > 0 ? Loc.Pick("Ransomware bloqueado", "Ransomware blocked") : Loc.Pick("Possível ransomware", "Possible ransomware"),
            Message = stopped.Count > 0 ? string.Join(", ", stopped) + " · " + reason : reason,
        });

        lock (_watchers) foreach (var dir in _folders) EnsureCanaries(dir);
    }

    private static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", "smss.exe",
        "dwm.exe", "System", "SearchIndexer.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe", "MsMpEng.exe",
        "MpDefenderCoreService.exe", "OneDrive.exe", "FileCoAuth.exe", "SgrmBroker.exe", "audiodg.exe", "fontdrvhost.exe",
        "sihost.exe", "taskhostw.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
    };

    private bool IsCritical(string exe) =>
        CriticalNames.Contains(Path.GetFileName(exe))
        || exe.StartsWith(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..")), StringComparison.OrdinalIgnoreCase);

    private IEnumerable<(int Pid, string Exe)> RecentSuspects(TimeSpan window)
    {
        var since = DateTime.Now - window;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                DateTime started;
                try { started = p.StartTime; } catch (Exception) { continue; }
                if (started < since || p.Id == Environment.ProcessId) continue;
                var exe = ImagePathOf(p.Id);
                if (exe is null || IsCritical(exe)) continue;
                var name = Path.GetFileName(exe);
                if (CommandLineAnalyzer.ScriptHosts.Contains(name))
                {
                    if (CommandLineOf(p.Id) is string cmd && CommandLineAnalyzer.Analyze(_state.Engine, name, cmd).Score >= 40) yield return (p.Id, exe);
                }
                else if (!IsTrustedImage(exe)) yield return (p.Id, exe);
            }
        }
    }

    private bool IsTrustedImage(string exe)
    {
        if (TrustedRoots.Any(r => exe.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase))) return true;
        if (exe.StartsWith(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..")), StringComparison.OrdinalIgnoreCase)) return true;
        try
        {
            var sha = SignatureDatabase.Sha256Hex(File.ReadAllBytes(exe));
            if (_state.Engine.Trust.IsTrusted(sha) || _state.Engine.Signatures.IsAllowed(sha)) return true;
        }
        catch (Exception) { }
        return FileContext.VerifySignature(exe).State == SignatureState.Valid;
    }

    private static string? CommandLineOf(int pid)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (System.Management.ManagementObject o in searcher.Get())
                using (o) return o["CommandLine"] as string;
        }
        catch (Exception) { }
        return null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static string? ImagePathOf(int pid)
    {
        var h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            var size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }

    private static class RestartManager
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
            public int ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
        }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmStartSession(out uint handle, int flags, StringBuilder key);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmEndSession(uint handle);

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
        private static extern int RmRegisterResources(uint handle, uint nFiles, string[] files, uint nApps, RM_UNIQUE_PROCESS[]? apps, uint nServices, string[]? services);

        [DllImport("rstrtmgr.dll")]
        private static extern int RmGetList(uint handle, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[]? info, ref uint rebootReasons);

        public static List<int> ProcessesUsing(string path)
        {
            var result = new List<int>();
            if (!OperatingSystem.IsWindows() || !File.Exists(path)) return result;
            var key = new StringBuilder(Guid.NewGuid().ToString());
            if (RmStartSession(out var handle, 0, key) != 0) return result;
            try
            {
                if (RmRegisterResources(handle, 1, new[] { path }, 0, null, 0, null) != 0) return result;
                uint count = 0, reasons = 0;
                var rc = RmGetList(handle, out var needed, ref count, null, ref reasons);
                if (rc != 234 || needed == 0) return result;
                var info = new RM_PROCESS_INFO[needed];
                count = needed;
                if (RmGetList(handle, out _, ref count, info, ref reasons) != 0) return result;
                for (var i = 0; i < count; i++) result.Add(info[i].Process.dwProcessId);
            }
            finally { RmEndSession(handle); }
            return result;
        }
    }
}
