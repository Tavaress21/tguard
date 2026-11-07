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

        _single = new Mutex(true, @"Local\TGuard.App.Single", out var first);
        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\TGuard.App.Show");
        if (!first)
        {
            _showSignal.Set();
            Shutdown();
            return;
        }
        new Thread(() => { while (_showSignal.WaitOne()) Dispatcher.Invoke(ShowMain); }) { IsBackground = true }.Start();

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
            if (n.Kind == "app-update-available")
            {
                Dispatcher.BeginInvoke(async () =>
                {
                    _tray?.Notify(n.Title, n.Message, false);
                    if (MainWindow?.IsVisible == true) await PromptAsync();
                });
                return;
            }
            if (n.Kind is "threat" or "scan-done" or "usb" or "usb-done" or "ransomware" or "email" or "remote" && Backend.NotificationsEnabled && !string.IsNullOrEmpty(n.Title))
                Dispatcher.BeginInvoke(() => _tray?.Notify(n.Title, n.Message, n.Kind is "threat" or "ransomware"));
        };

        Backend.Reconnected += () => Dispatcher.BeginInvoke(() => win.RefreshCurrent());
        var reconnect = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
        reconnect.Tick += async (_, _) => { if (!Backend.ServiceAvailable) await Backend.ConnectAsync(); };
        reconnect.Start();

        win.IsVisibleChanged += async (_, _) => { if (win.IsVisible) await PromptAsync(); };
        if (!args.Contains("--tray")) win.Show();
    }

    private bool _prompting;

    private async Task PromptAsync()
    {
        if (_prompting || !Backend.ServiceAvailable || Backend.Showcase is not null) return;
        _prompting = true;
        try
        {
            var settings = await Backend.GetSettingsAsync();
            if (!settings.PrivacyAsked)
            {
                var share = Views.Dialog.Ask(S.T("privacy.title"), S.T("privacy.message"), S.T("privacy.yes"), S.T("privacy.no"));
                settings.UsageStats = share;
                settings.CommunitySharing = share;
                settings.PrivacyAsked = true;
                await Backend.SaveSettingsAsync(settings);
            }

            var pending = await Backend.PendingUpdateAsync();
            if (pending is not null && (pending.SnoozedUntil is null || pending.SnoozedUntil < DateTimeOffset.Now))
            {
                if (Views.Dialog.Ask(S.T("upd.title"), S.F("upd.message", pending.Version), S.T("upd.now"), S.T("upd.later"), Views.DialogKind.Success))
                    await Backend.InstallUpdateAsync();
                else
                    await Backend.SnoozeUpdateAsync();
            }
        }
        catch (Exception) { }
        finally { _prompting = false; }
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
