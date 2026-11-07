using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using System.Diagnostics;
using System.Threading;
using TGuard.App.Services;
using TGuard.Core.Online;
using TGuard.Core.Storage;

namespace TGuard.App.Views;

public partial class SettingsView : UserControl, IRefreshable
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private TGuardSettings _settings = new();
    private AccountStatus? _account;
    private CancellationTokenSource? _linking;
    private bool _linkCancelled;

    public SettingsView()
    {
        InitializeComponent();
        for (int h = 0; h < 24; h++) Hour.Items.Add($"{h:00}:00");
        About.Text = S.F("set.about.text", "v" + typeof(SettingsView).Assembly.GetName().Version?.ToString(3));
    }

    public async Task RefreshAsync()
    {
        _settings = await App.Backend.GetSettingsAsync();
        LanguageBox.SelectedIndex = _settings.Language == "en" ? 1 : 0;
        Realtime.IsChecked = _settings.RealtimeEnabled;
        Realtime.IsEnabled = App.Backend.ServiceAvailable;
        AutoQuarantine.IsChecked = _settings.AutoQuarantine;
        ProcessGuard.IsChecked = _settings.ProcessGuardEnabled;
        ProcessGuard.IsEnabled = App.Backend.ServiceAvailable;
        UsbScan.IsChecked = _settings.UsbScanEnabled;
        UsbScan.IsEnabled = App.Backend.ServiceAvailable;
        AutoUpdate.IsChecked = _settings.AutoUpdate;
        AutoInstall.IsChecked = _settings.AutoInstallUpdates;
        AutoInstall.IsEnabled = App.Backend.ServiceAvailable;
        AbuseKey.Text = _settings.AbuseChAuthKey;
        Notifications.IsChecked = _settings.Notifications;
        Scheduled.IsChecked = _settings.ScheduledQuickScan;
        Hour.SelectedIndex = Math.Clamp(_settings.ScheduledQuickScanHour, 0, 23);
        Community.IsChecked = _settings.CommunitySharing;
        Folders.Text = string.Join(Environment.NewLine, _settings.WatchFolders);
        Exclusions.Text = string.Join(Environment.NewLine, _settings.Exclusions);
        Startup.IsChecked = IsInStartup();
        UsageStats.IsChecked = _settings.UsageStats;
        Ransomware.IsChecked = _settings.RansomwareProtection;
        Ransomware.IsEnabled = App.Backend.ServiceAvailable;
        EmailOn.IsChecked = _settings.EmailProtection;
        EmailOn.IsEnabled = App.Backend.ServiceAvailable;
        AddEmailButton.IsEnabled = App.Backend.ServiceAvailable;
        await ShowEmailAccountsAsync();
        UsageStats.IsEnabled = App.Backend.ServiceAvailable;
        RemoteControl.IsChecked = _settings.RemoteControl;
        Saved.Text = "";
        if (_linking is null) ShowAccount(await App.Backend.AccountAsync());
    }

    private void ShowAccount(AccountStatus? account)
    {
        _account = account;
        var linked = account?.Linked == true;
        AccountTitle.Text = linked ? S.F("acc.linked", account!.Email ?? account.Name ?? "") : S.T("acc.none");
        AccountNote.Text = linked ? S.T("acc.linked.note") : S.T("acc.none.note");
        LinkButton.Content = linked ? S.T("acc.unlink") : S.T("acc.link");
        LinkButton.IsEnabled = App.Backend.ServiceAvailable;
        RemoteControl.IsEnabled = linked && App.Backend.ServiceAvailable;
        RemoteNote.Text = linked ? S.T("acc.remote.note") : S.T("acc.remote.off");
    }

    private async void Link_Click(object sender, RoutedEventArgs e)
    {
        if (_linking is not null)
        {
            _linkCancelled = true;
            _linking.Cancel();
            return;
        }
        try
        {
            if (_account?.Linked == true)
            {
                if (!Dialog.Confirm(S.T("acc.unlink"), S.T("acc.unlink.confirm"), S.T("acc.unlink"))) return;
                ShowAccount(await App.Backend.UnlinkAsync());
                return;
            }
            await LinkAsync();
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), QuarantineView.Friendly(ex), DialogKind.Danger); }
    }

    private async Task LinkAsync()
    {
        var start = await App.Backend.StartLinkAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Clamp(start.ExpiresIn, 60, 1800)));
        _linking = cts;
        _linkCancelled = false;
        AccountTitle.Text = S.F("acc.waiting", start.Code);
        AccountNote.Text = S.F("acc.waiting.note", start.Code, start.Url);
        LinkButton.Content = S.T("acc.cancel");
        Open(start.Url);
        try
        {
            while (true)
            {
                await Task.Delay(3000, cts.Token);
                var (linked, expired, account) = await App.Backend.PollLinkAsync(start.Secret);
                if (linked)
                {
                    ShowAccount(account);
                    return;
                }
                if (expired) break;
            }
        }
        catch (OperationCanceledException) { }
        finally { _linking = null; }
        ShowAccount(await App.Backend.AccountAsync());
        if (!_linkCancelled) AccountNote.Text = S.T("acc.expired");
    }

    private async Task ShowEmailAccountsAsync()
    {
        var accounts = await App.Backend.EmailAccountsAsync();
        EmailAccounts.ItemsSource = accounts.Select(a => new EmailRow(a)).ToList();
        EmailNone.Visibility = accounts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void AddEmail_Click(object sender, RoutedEventArgs e)
    {
        AddEmailButton.IsEnabled = false;
        AddEmailButton.Content = S.T("email.adding");
        try
        {
            await App.Backend.AddEmailAsync(EmailUser.Text.Trim(), EmailPassword.Password, EmailHost.Text.Trim(), EmailMove.IsChecked == true);
            EmailPassword.Clear();
            EmailUser.Clear();
            EmailHost.Clear();
            Saved.Text = S.T("email.added");
            await ShowEmailAccountsAsync();
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), QuarantineView.Friendly(ex), DialogKind.Danger); }
        finally
        {
            AddEmailButton.Content = S.T("email.add");
            AddEmailButton.IsEnabled = App.Backend.ServiceAvailable;
        }
    }

    private async void RemoveEmail_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is not string id) return;
        try
        {
            await App.Backend.RemoveEmailAsync(id);
            await ShowEmailAccountsAsync();
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), QuarantineView.Friendly(ex), DialogKind.Danger); }
    }

    private void InstallWeb_Click(object sender, RoutedEventArgs e)
    {
        var dir = System.IO.Path.GetFullPath(System.IO.Path.Combine(AppContext.BaseDirectory, "..", "browser"));
        if (!System.IO.Directory.Exists(dir)) dir = System.IO.Path.Combine(AppContext.BaseDirectory, "browser");
        if (System.IO.Directory.Exists(dir))
        {
            try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true }); }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
        }
        Dialog.Alert(S.T("web.install"), S.T("web.steps") + "\n\n" + dir, DialogKind.Info);
    }

    private void Help_Click(object sender, RoutedEventArgs e) => (Application.Current.MainWindow as MainWindow)?.Navigate("help");

    private void ReportScam_Click(object sender, RoutedEventArgs e) => Open(SiteClient.ReportUrl(_settings));

    private void Site_Click(object sender, RoutedEventArgs e) => Open(SiteClient.AccountUrl(_settings));

    private static void Open(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { Dialog.Alert(S.T("error"), url, DialogKind.Danger); }
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        _settings.Language = (string)((ComboBoxItem)LanguageBox.SelectedItem).Tag;
        _settings.RealtimeEnabled = Realtime.IsChecked == true;
        _settings.AutoQuarantine = AutoQuarantine.IsChecked == true;
        _settings.ProcessGuardEnabled = ProcessGuard.IsChecked == true;
        _settings.UsbScanEnabled = UsbScan.IsChecked == true;
        _settings.AutoUpdate = AutoUpdate.IsChecked == true;
        _settings.AutoInstallUpdates = AutoInstall.IsChecked == true;
        _settings.AbuseChAuthKey = AbuseKey.Text.Trim();
        _settings.Notifications = Notifications.IsChecked == true;
        _settings.ScheduledQuickScan = Scheduled.IsChecked == true;
        _settings.ScheduledQuickScanHour = Math.Max(0, Hour.SelectedIndex);
        _settings.StartWithWindows = Startup.IsChecked == true;
        _settings.WatchFolders = Lines(Folders.Text);
        _settings.Exclusions = Lines(Exclusions.Text);
        _settings.UsageStats = UsageStats.IsChecked == true;
        _settings.CommunitySharing = Community.IsChecked == true;
        _settings.RemoteControl = RemoteControl.IsEnabled && RemoteControl.IsChecked == true;
        _settings.PrivacyAsked = true;
        _settings.RansomwareProtection = Ransomware.IsChecked == true;
        _settings.EmailProtection = EmailOn.IsChecked == true;
        try
        {
            await App.Backend.SaveSettingsAsync(_settings);
            SetStartup(_settings.StartWithWindows);
            Saved.Text = S.T("set.saved");
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), QuarantineView.Friendly(ex), DialogKind.Danger); }
    }

    private static System.Collections.Generic.List<string> Lines(string text) =>
        text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();

    private static bool IsInStartup()
    {
        using var k = Registry.CurrentUser.OpenSubKey(RunKey);
        return k?.GetValue("TGuard") is string;
    }

    private static void SetStartup(bool on)
    {
        using var k = Registry.CurrentUser.CreateSubKey(RunKey);
        if (on) k.SetValue("TGuard", $"\"{Environment.ProcessPath}\" --tray");
        else if (k.GetValue("TGuard") is not null) k.DeleteValue("TGuard");
    }
}
