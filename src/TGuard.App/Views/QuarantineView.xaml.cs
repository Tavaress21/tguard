using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using TGuard.App.Services;
using TGuard.Core.Online;

namespace TGuard.App.Views;

public sealed record TrustedRow(string Sha256, string Title, string Detail);

public partial class QuarantineView : UserControl, IRefreshable
{
    public QuarantineView() => InitializeComponent();

    public async Task RefreshAsync()
    {
        var items = (await App.Backend.QuarantineAsync()).Select(q => new QuarantineRow(q)).ToList();
        Items.ItemsSource = items;
        Empty.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var trusted = (await App.Backend.TrustedAsync())
            .Select(t => new TrustedRow(t.Sha256, System.IO.Path.GetFileName(t.Path), $"{t.Date:dd/MM/yyyy}  ·  SHA-256 {t.Sha256[..16]}…"))
            .ToList();
        Trusted.ItemsSource = trusted;
        TrustedSection.Visibility = trusted.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (!Dialog.Confirm(S.T("q.restore.title"), S.T("q.restore.confirm") + "\n\n" + S.T("q.restore.note"), S.T("q.restore"))) return;
        try
        {
            var path = await App.Backend.RestoreAsync((string)((Button)sender).Tag);
            Dialog.Alert(S.T("q.restored.title"), S.F("q.restored", path), DialogKind.Success);
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), Friendly(ex), DialogKind.Danger); }
        await RefreshAsync();
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (!Dialog.Confirm(S.T("q.delete.title"), S.T("q.delete.confirm"), S.T("q.delete"), DialogKind.Danger)) return;
        try { await App.Backend.DeleteAsync((string)((Button)sender).Tag); }
        catch (Exception ex) { Dialog.Alert(S.T("error"), Friendly(ex), DialogKind.Danger); }
        await RefreshAsync();
    }

    private async void Report_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is not QuarantineRow row) return;
        if (!Dialog.Confirm(S.T("q.report.title"), S.T("q.report.confirm"), S.T("q.report.send"))) return;
        try
        {
            await App.Backend.ReportAsync(new ReportRequest
            {
                Type = "false_positive",
                Value = row.Sha256,
                FileName = row.Title,
                Detection = row.Threat,
                Details = row.Reasons,
            });
            Dialog.Alert(S.T("q.report.done.title"), S.T("q.report.done"), DialogKind.Success);
        }
        catch (Exception ex) { Dialog.Alert(S.T("error"), Friendly(ex), DialogKind.Danger); }
    }

    private async void Untrust_Click(object sender, RoutedEventArgs e)
    {
        try { await App.Backend.RemoveTrustAsync((string)((Button)sender).Tag); }
        catch (Exception ex) { Dialog.Alert(S.T("error"), Friendly(ex), DialogKind.Danger); }
        await RefreshAsync();
    }

    public static string Friendly(Exception ex) =>
        ex.Message.StartsWith("ACCESS_DENIED", StringComparison.Ordinal) ? S.T("service.denied") : ex.Message;
}
