using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TGuard.App.Services;

namespace TGuard.App.Views;

public partial class DashboardView : UserControl, IRefreshable
{
    public DashboardView() => InitializeComponent();

    public async Task RefreshAsync()
    {
        var b = App.Backend;
        var st = await b.GetStatusAsync();
        var events = await b.EventsAsync();

        var rtOn = st.RealtimeEnabled && b.ServiceAvailable;
        TileRealtime.Text = rtOn ? S.T("on") : S.T("off");
        TileRealtime.Foreground = Palette.B(rtOn ? "Good" : "Bad");
        RealtimeTile.Background = Palette.B(rtOn ? "GoodSoft" : "BadSoft");
        RealtimeIcon.Foreground = Palette.B(rtOn ? "Good" : "Bad");
        TileRealtimeSub.Text = rtOn ? S.F("folders", st.WatchedFolders) : "";
        TileThreats.Text = st.ThreatsLast30Days.ToString();
        TileQuarantine.Text = st.QuarantineCount.ToString();
        TileLastScan.Text = Palette.Ago(st.LastScan);
        EngineRules.Text = st.Rules.ToString();
        EngineSignatures.Text = st.Signatures.ToString("N0");
        EngineMode.Text = b.ServiceAvailable ? S.T("dash.mode.service") : S.T("dash.mode.local");
        EngineVersion.Text = st.Version;
        EngineBadUrls.Text = st.BadUrls.ToString("N0");
        EngineLastUpdate.Text = Palette.Ago(st.LastUpdate);

        var recentThreat = events.Any(e => e.Verdict == "malicious" && e.Date > DateTimeOffset.Now.AddDays(-1) && string.IsNullOrEmpty(e.Action));
        var main = Window.GetWindow(this) as MainWindow;
        if (!b.ServiceAvailable)
        {
            SetHero("dash.local", "dash.local.sub", Glyph.Info, "Info", "InfoSoft", "#EEF1FF");
            main?.SetStatus(S.T("status.local"), "info");
        }
        else if (!st.RealtimeEnabled || recentThreat)
        {
            SetHero("dash.attention", "dash.attention.sub", Glyph.Warning, "Warn", "WarnSoft", "#FEF4E2");
            main?.SetStatus(S.T("status.warn"), "warn");
        }
        else
        {
            SetHero("dash.protected", "dash.protected.sub", Glyph.Check, "Good", "GoodSoft", "#ECF8F0");
            main?.SetStatus(S.T("status.ok"), "ok");
        }

        var rows = events.OrderByDescending(e => e.Date).Take(5).Select(e => new EventRow(e)).ToList();
        RecentList.ItemsSource = rows;
        NoRecent.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SetHero(string title, string sub, string glyph, string fg, string bg, string tint)
    {
        HeroTitle.Text = S.T(title);
        HeroSub.Text = S.T(sub);
        HeroIcon.Text = glyph;
        HeroIcon.Foreground = Palette.B(fg);
        HeroRing.Stroke = Palette.B(fg);
        HeroCircle.Fill = Palette.B(bg);
        HeroTint.Color = (Color)ColorConverter.ConvertFromString(tint);
    }

    private void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        _ = App.Backend.StartScanAsync("quick");
        (Window.GetWindow(this) as MainWindow)?.Navigate("scan");
    }

    private async void Update_Click(object sender, RoutedEventArgs e)
    {
        UpdateButton.IsEnabled = false;
        UpdateButtonText.Text = S.T("dash.updating");
        try
        {
            var rep = await App.Backend.UpdateNowAsync();
            if (rep.Success) Dialog.Alert(S.T("update.done"), S.F("update.result", rep.SignaturesAdded.ToString("N0"), rep.UrlsAdded.ToString("N0")), DialogKind.Success);
            else if (rep.Notes.Any(n => n.StartsWith("abuse.ch"))) Dialog.Alert(S.T("dash.update"), S.T("update.nokey"), DialogKind.Info);
            else Dialog.Alert(S.T("error"), S.T("update.failed"), DialogKind.Warning);
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), QuarantineView.Friendly(ex), DialogKind.Danger); }
        UpdateButton.IsEnabled = true;
        UpdateButtonText.Text = S.T("dash.update");
        await RefreshAsync();
    }

    private void Check_Click(object sender, RoutedEventArgs e) => (Window.GetWindow(this) as MainWindow)?.Navigate("check");
    private void History_Click(object sender, RoutedEventArgs e) => (Window.GetWindow(this) as MainWindow)?.Navigate("history");
}
