using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using TGuard.App.Services;
using TGuard.Core.Ipc;

namespace TGuard.App.Views;

public partial class ScanView : UserControl, IRefreshable
{
    public ScanView()
    {
        InitializeComponent();
        App.Backend.Notified += OnNotified;
    }

    public async Task RefreshAsync()
    {
        var st = await App.Backend.GetStatusAsync();
        if (st.CurrentScan is not null) Show(st.CurrentScan);
    }

    private void OnNotified(Notification n)
    {
        if (n.Kind is not ("scan-progress" or "scan-done") || n.Data is null) return;
        var p = n.Data.Deserialize<ScanProgress>(Protocol.Json);
        if (p is not null) Dispatcher.BeginInvoke(() => Show(p));
    }

    public void Show(ScanProgress p)
    {
        ProgressCard.Visibility = Visibility.Visible;
        Bar.IsIndeterminate = p.Running;
        Bar.Value = p.Running ? 0 : 100;
        CancelButton.Visibility = p.Running ? Visibility.Visible : Visibility.Collapsed;
        ProgressTitle.Text = p.Running ? S.T("scan.running")
            : p.Cancelled ? S.T("scan.cancelled")
            : p.Threats == 0 ? S.T("scan.done.clean") : S.F("scan.done.threats", p.Threats);
        ProgressCounts.Text = S.F("scan.files", p.FilesScanned.ToString("N0"));
        ProgressThreats.Text = S.F("scan.threats", p.Threats);
        ProgressThreats.Foreground = Palette.B(p.Threats > 0 ? "Bad" : "Good");
        var (fg, bg, glyph) = p.Running ? ("Royal", "RoyalSoft", Glyph.Search)
            : p.Threats > 0 ? ("Bad", "BadSoft", Glyph.Warning)
            : p.Cancelled ? ("Warn", "WarnSoft", Glyph.Info) : ("Good", "GoodSoft", Glyph.Check);
        ProgressIcon.Text = glyph;
        ProgressIcon.Foreground = Palette.B(fg);
        ProgressIconTile.Background = Palette.B(bg);
        CurrentFile.Text = p.CurrentFile;
        List<ThreatInfo> found;
        lock (p.Found) found = p.Found.ToList();
        FoundCard.Visibility = found.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        FoundList.ItemsSource = found.Select(t => new ThreatRow(t)).ToList();
        foreach (var b in Options.Children.OfType<Border>().Select(x => x.Child).OfType<DockPanel>().SelectMany(d => d.Children.OfType<Button>()))
            b.IsEnabled = !p.Running;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        var type = (string)((Button)sender).Tag;
        List<string>? paths = null;
        if (type == "custom")
        {
            var dlg = new Microsoft.Win32.OpenFolderDialog { Multiselect = true };
            if (dlg.ShowDialog() != true) return;
            paths = dlg.FolderNames.ToList();
        }
        var p = await App.Backend.StartScanAsync(type, paths);
        if (p is not null) Show(p);
    }

    private async void Cancel_Click(object sender, RoutedEventArgs e) => await App.Backend.CancelScanAsync();
}
