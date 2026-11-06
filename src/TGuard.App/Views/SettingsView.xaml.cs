using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using TGuard.App.Services;
using TGuard.Core.Storage;

namespace TGuard.App.Views;

public partial class SettingsView : UserControl, IRefreshable
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private TGuardSettings _settings = new();

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
        AbuseKey.Text = _settings.AbuseChAuthKey;
        Notifications.IsChecked = _settings.Notifications;
        Scheduled.IsChecked = _settings.ScheduledQuickScan;
        Hour.SelectedIndex = Math.Clamp(_settings.ScheduledQuickScanHour, 0, 23);
        Community.IsChecked = _settings.CommunitySharing;
        Folders.Text = string.Join(Environment.NewLine, _settings.WatchFolders);
        Exclusions.Text = string.Join(Environment.NewLine, _settings.Exclusions);
        Startup.IsChecked = IsInStartup();
        Saved.Text = "";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        _settings.Language = (string)((ComboBoxItem)LanguageBox.SelectedItem).Tag;
        _settings.RealtimeEnabled = Realtime.IsChecked == true;
        _settings.AutoQuarantine = AutoQuarantine.IsChecked == true;
        _settings.ProcessGuardEnabled = ProcessGuard.IsChecked == true;
        _settings.UsbScanEnabled = UsbScan.IsChecked == true;
        _settings.AutoUpdate = AutoUpdate.IsChecked == true;
        _settings.AbuseChAuthKey = AbuseKey.Text.Trim();
        _settings.Notifications = Notifications.IsChecked == true;
        _settings.ScheduledQuickScan = Scheduled.IsChecked == true;
        _settings.ScheduledQuickScanHour = Math.Max(0, Hour.SelectedIndex);
        _settings.StartWithWindows = Startup.IsChecked == true;
        _settings.WatchFolders = Lines(Folders.Text);
        _settings.Exclusions = Lines(Exclusions.Text);
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
