using System.Windows;
using System.Windows.Input;
using TGuard.App.Services;

namespace TGuard.App.Views;

public enum DialogKind { Info, Warning, Danger, Success }

public partial class Dialog : Window
{
    private Dialog(string title, string message, string ok, string? cancel, DialogKind kind)
    {
        InitializeComponent();
        TitleText.Text = title;
        MessageText.Text = message;
        OkButton.Content = ok;
        if (cancel is null) CancelButton.Visibility = Visibility.Collapsed;
        else CancelButton.Content = cancel;
        var (fg, bg, glyph) = kind switch
        {
            DialogKind.Danger => ("Bad", "BadSoft", Glyph.Warning),
            DialogKind.Warning => ("Warn", "WarnSoft", Glyph.Warning),
            DialogKind.Success => ("Good", "GoodSoft", Glyph.Check),
            _ => ("Info", "InfoSoft", Glyph.Info),
        };
        IconGlyph.Text = glyph;
        IconGlyph.Foreground = Palette.B(fg);
        IconCircle.Fill = Palette.B(bg);
        if (kind == DialogKind.Danger)
        {
            OkButton.Background = Palette.B("Bad");
            OkButton.BorderBrush = Palette.B("Bad");
        }
        MouseLeftButtonDown += (_, e) => { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); };
    }

    private void Ok_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private static Window? OwnerWindow() =>
        Application.Current.MainWindow is { IsVisible: true } w ? w : null;

    internal static Dialog Preview(string title, string message, string ok, DialogKind kind) => new(title, message, ok, S.T("cancel"), kind);

    public static bool Confirm(string title, string message, string ok, DialogKind kind = DialogKind.Warning) =>
        new Dialog(title, message, ok, S.T("cancel"), kind) { Owner = OwnerWindow() }.ShowDialog() == true;

    public static void Alert(string title, string message, DialogKind kind = DialogKind.Info) =>
        new Dialog(title, message, "OK", null, kind) { Owner = OwnerWindow() }.ShowDialog();
}
