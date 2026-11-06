using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using TGuard.App.Services;
using TGuard.Core.Security;

namespace TGuard.App.Views;

public partial class CheckView : UserControl, IRefreshable
{
    private bool _ran;

    public CheckView() => InitializeComponent();

    public async Task RefreshAsync()
    {
        if (!_ran) await RunAsync();
    }

    public void Show(List<CheckItem> items)
    {
        var ordered = items.OrderByDescending(i => i.Status).ToList();
        Items.ItemsSource = ordered.Select(i => new CheckRow(i)).ToList();
        Summary.Text = S.F("check.summary", items.Count, items.Count(i => i.Status is CheckStatus.Warning or CheckStatus.Critical));
    }

    private async Task RunAsync()
    {
        _ran = true;
        RunButton.IsEnabled = false;
        Summary.Text = S.T("check.running");
        Show(await App.Backend.CheckAsync());
        RunButton.IsEnabled = true;
    }

    private async void Run_Click(object sender, RoutedEventArgs e) => await RunAsync();
}
