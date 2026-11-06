using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using TGuard.Core;
using TGuard.Core.Engine;

namespace TGuard.Service;

public sealed class ProcessGuard : BackgroundService
{
    private readonly ServiceState _state;
    private readonly ILogger<ProcessGuard> _log;
    private readonly Channel<int> _queue = Channel.CreateBounded<int>(new BoundedChannelOptions(2000) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly SemaphoreSlim _workers = new(4);
    private static readonly string InstallRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, ".."));
    private static readonly string[] SystemDirs =
    {
        Environment.SystemDirectory,
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "servicing"),
    };

    public bool Active { get; private set; }

    public ProcessGuard(ServiceState state, ILogger<ProcessGuard> log)
    {
        _state = state;
        _log = log;
    }

    protected override Task ExecuteAsync(CancellationToken ct)
    {
        _ = Task.Run(() => ConsumeAsync(ct), ct);
        return Task.Run(() => Watch(ct), ct);
    }

    private void Watch(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            if (!_state.Settings.ProcessGuardEnabled)
            {
                Active = false;
                ct.WaitHandle.WaitOne(3000);
                continue;
            }
            try
            {
                using var watcher = new ManagementEventWatcher(new WqlEventQuery("Win32_ProcessStartTrace"));
                watcher.EventArrived += (_, e) =>
                {
                    try { _queue.Writer.TryWrite(Convert.ToInt32(e.NewEvent["ProcessID"])); }
                    catch (Exception) { }
                };
                watcher.Start();
                Active = true;
                _log.LogInformation("Process guard active");
                while (!ct.IsCancellationRequested && _state.Settings.ProcessGuardEnabled) ct.WaitHandle.WaitOne(1000);
                watcher.Stop();
            }
            catch (Exception ex)
            {
                Active = false;
                _log.LogWarning(ex, "Process guard could not subscribe to process events, retrying in 30s");
                ct.WaitHandle.WaitOne(30_000);
            }
        }
        Active = false;
    }

    private async Task ConsumeAsync(CancellationToken ct)
    {
        await foreach (var pid in _queue.Reader.ReadAllAsync(ct))
        {
            await _workers.WaitAsync(ct);
            _ = Task.Run(() =>
            {
                try { Inspect(pid); }
                catch (Exception ex) { _log.LogDebug(ex, "Could not inspect pid {Pid}", pid); }
                finally { _workers.Release(); }
            }, ct);
        }
    }

    public void Inspect(int pid)
    {
        if (pid == Environment.ProcessId) return;
        var exe = ImagePath(pid);
        if (exe is null || exe.StartsWith(InstallRoot, StringComparison.OrdinalIgnoreCase)) return;
        var name = Path.GetFileName(exe);
        var engine = _state.Engine;

        if (!SystemDirs.Any(d => exe.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase)))
        {
            var r = engine.ScanFile(exe);
            if (r.Verdict == Verdict.Malicious)
            {
                var killed = Kill(pid);
                _state.Handle(r, "process", extraAction: killed ? Loc.Pick("Processo terminado", "Process terminated") : null);
                return;
            }
        }

        if (!CommandLineAnalyzer.ScriptHosts.Contains(name)) return;
        var cmd = CommandLine(pid);
        if (string.IsNullOrWhiteSpace(cmd)) return;

        foreach (var file in CommandLineAnalyzer.ReferencedFiles(cmd).Where(File.Exists))
        {
            var r = engine.ScanFile(file);
            if (r.Verdict == Verdict.Malicious)
            {
                var killed = Kill(pid);
                _state.Handle(r, "process", extraAction: killed ? Loc.Pick($"{name} terminado", $"{name} terminated") : null);
                return;
            }
        }

        var c = CommandLineAnalyzer.Analyze(engine, name, cmd);
        if (c.Verdict == Verdict.Malicious)
        {
            var killed = Kill(pid);
            var shown = new ScanResult { Name = $"{name}: {Truncate(cmd, 240)}", Score = c.Score, Verdict = c.Verdict, ThreatName = c.ThreatName };
            shown.Findings.AddRange(c.Findings);
            _state.Handle(shown, "process", allowQuarantine: false,
                extraAction: killed ? Loc.Pick("Processo terminado", "Process terminated") : Loc.Pick("Não foi possível terminar", "Could not terminate"));
        }
        else if (c.Verdict == Verdict.Suspicious)
        {
            var shown = new ScanResult { Name = $"{name}: {Truncate(cmd, 240)}", Score = c.Score, Verdict = c.Verdict };
            shown.Findings.AddRange(c.Findings);
            _state.Handle(shown, "process", allowQuarantine: false);
        }
    }

    private bool Kill(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
            p.WaitForExit(3000);
            return true;
        }
        catch (ArgumentException) { return true; }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Could not terminate pid {Pid}", pid);
            return false;
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";

    private static string? CommandLine(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject o in searcher.Get())
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

    private static string? ImagePath(int pid)
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
}
