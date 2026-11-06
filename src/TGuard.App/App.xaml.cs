using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using TGuard.App.Services;
using TGuard.Core;
using TGuard.Core.Storage;

namespace TGuard.App;

public partial class App : Application
{
    private Mutex? _single;
    private EventWaitHandle? _showSignal;
    private TrayIcon? _tray;

    public static Backend Backend { get; internal set; } = null!;
    public static new App Current => (App)Application.Current;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var args = e.Args;

        // CI mode: render every page to PNG and exit.
        var selfTest = Array.IndexOf(args, "--selftest");
        if (selfTest >= 0)
        {
            Loc.Language = args.Contains("--en") ? "en" : "pt";
            ApplyCulture();
            var outDir = selfTest + 1 < args.Length ? args[selfTest + 1] : "selftest";
            var code = await SelfTest.RunAsync(outDir);
            Shutdown(code);
            return;
        }

        // Single instance: a second launch asks the first one to show its window.
        _single = new Mutex(true, @"Local\TGuard.App.Single", out var first);
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\TGuard.App.Show");
        if (!first)
        {
            _showSignal.Set();
            Shutdown();
            return;
        }
        new Thread(() => { while (_showSignal.WaitOne()) Dispatcher.Invoke(ShowMain); }) { IsBackground = true }.Start();

        // Backend decides where data lives (service vs local mode) before settings are read
        Backend = new Backend();
        await Backend.ConnectAsync();
        Loc.Language = (await Backend.GetSettingsAsync()).Language;
        ApplyCulture();

        var win = new MainWindow();
        MainWindow = win;
        _tray = new TrayIcon(ShowMain, () => { ShowMain(); win.Navigate("scan"); _ = Backend.StartScanAsync("quick"); }, ExitApp);
        Backend.Notified += n =>
        {
            if (n.Kind == "app-update")
            {
                Dispatcher.BeginInvoke(() =>
                {
                    _tray?.Notify(n.Title, n.Message, false);
                    RelaunchAfterUpdate();
                });
                return;
            }
            if (n.Kind is "threat" or "scan-done" or "usb" or "usb-done" && Backend.NotificationsEnabled && !string.IsNullOrEmpty(n.Title))
                Dispatcher.BeginInvoke(() => _tray?.Notify(n.Title, n.Message, n.Kind == "threat"));
        };

        if (!args.Contains("--tray")) win.Show();
    }

    private static void ApplyCulture()
    {
        var c = System.Globalization.CultureInfo.GetCultureInfo(Loc.IsEnglish ? "en-GB" : "pt-PT");
        System.Globalization.CultureInfo.DefaultThreadCurrentCulture = c;
        System.Globalization.CultureInfo.DefaultThreadCurrentUICulture = c;
        Thread.CurrentThread.CurrentCulture = c;
        Thread.CurrentThread.CurrentUICulture = c;
        FrameworkElement.LanguageProperty.OverrideMetadata(typeof(FrameworkElement),
            new FrameworkPropertyMetadata(System.Windows.Markup.XmlLanguage.GetLanguage(c.IetfLanguageTag)));
    }

    /// <summary>
    /// The installer closes this app while it updates. A small hidden PowerShell waits for the
    /// new version's service to come back and then starts the app again in the tray.
    /// </summary>
    private void RelaunchAfterUpdate()
    {
        var exe = Environment.ProcessPath ?? "";
        if (exe.Length == 0) return;
        var script = $"$exe='{exe.Replace("'", "''")}'; Start-Sleep -Seconds 15; " +
                     "for ($i = 0; $i -lt 60; $i++) { $s = Get-Service TGuard -ErrorAction SilentlyContinue; " +
                     "if ($s -and $s.Status -eq 'Running' -and (Test-Path $exe) -and -not (Get-Process TGuard -ErrorAction SilentlyContinue)) " +
                     "{ Start-Process $exe '--tray'; break }; Start-Sleep -Seconds 5 }";
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("powershell.exe",
                $"-NoProfile -WindowStyle Hidden -Command \"{script}\"") { UseShellExecute = false, CreateNoWindow = true });
        }
        catch (Exception) { }
    }

    public void ShowMain()
    {
        if (MainWindow is null) return;
        MainWindow.Show();
        if (MainWindow.WindowState == WindowState.Minimized) MainWindow.WindowState = WindowState.Normal;
        MainWindow.Activate();
    }

    public void HideToTray()
    {
        MainWindow?.Hide();
        _tray?.Notify("TGuard", S.T("tray.running"), false, onlyOnce: true);
    }

    public void ExitApp()
    {
        Backend?.Stop();
        _tray?.Dispose();
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _single?.Dispose();
        base.OnExit(e);
    }
}
