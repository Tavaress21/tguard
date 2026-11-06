using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using TGuard.App.Views;

namespace TGuard.App;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, UserControl> _views = new();
    public bool ReallyClose { get; set; }

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = "TGuard v" + typeof(MainWindow).Assembly.GetName().Version?.ToString(3) + " · luis-tavares.pt";
        NavDashboard.IsChecked = true;
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_StateChanged(object? sender, System.EventArgs e)
    {
        RootGrid.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);
        MaxButton.Content = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
    }

    public void SetStatus(string text, string level)
    {
        StatusText.Text = text;
        StatusDot.Fill = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(
            level switch { "ok" => "#4ADE80", "warn" => "#FBBF24", _ => "#93A4FF" }));
    }

    public UserControl CreateView(string key) => key switch
    {
        "scan" => new ScanView(),
        "protections" => new ProtectionsView(),
        "quarantine" => new QuarantineView(),
        "check" => new CheckView(),
        "history" => new HistoryView(),
        "settings" => new SettingsView(),
        _ => new DashboardView(),
    };

    public void Navigate(string key)
    {
        var radio = FindRadios(this).FirstOrDefault(r => (string?)r.Tag == key);
        if (radio is not null && radio.IsChecked != true) { radio.IsChecked = true; return; }
        if (!_views.TryGetValue(key, out var view)) _views[key] = view = CreateView(key);
        Host.Content = view;
        if (view is IRefreshable r) _ = r.RefreshAsync();
    }

    public void RefreshCurrent()
    {
        if (Host.Content is IRefreshable r) _ = r.RefreshAsync();
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string key }) Navigate(key);
    }

    private static IEnumerable<RadioButton> FindRadios(DependencyObject root)
    {
        foreach (var c in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
        {
            if (c is RadioButton rb) yield return rb;
            foreach (var x in FindRadios(c)) yield return x;
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!ReallyClose)
        {
            e.Cancel = true;
            App.Current.HideToTray();
        }
        base.OnClosing(e);
    }
}

public interface IRefreshable
{
    System.Threading.Tasks.Task RefreshAsync();
}
