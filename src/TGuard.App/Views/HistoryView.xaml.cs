using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace TGuard.App.Views;

public partial class HistoryView : UserControl, IRefreshable
{
    public HistoryView() => InitializeComponent();

    public async Task RefreshAsync()
    {
        var rows = (await App.Backend.EventsAsync()).OrderByDescending(e => e.Date).Select(e => new EventRow(e)).ToList();
        Items.ItemsSource = rows;
        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }
}
