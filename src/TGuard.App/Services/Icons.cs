using System;
using System.Globalization;
using System.Windows.Data;

namespace TGuard.App.Services;

public static class Glyph
{
    public const string Home = "";
    public const string Search = "";
    public const string Shield = "";
    public const string Package = "";
    public const string Diagnostic = "";
    public const string History = "";
    public const string Settings = "";
    public const string Check = "";
    public const string Info = "";
    public const string Warning = "";
    public const string Cancel = "";
    public const string Calendar = "";
    public const string Mail = "";
    public const string Lock = "";
    public const string Globe = "";
    public const string Usb = "";
    public const string Lightning = "";
    public const string HardDrive = "";
    public const string Folder = "";
    public const string Recent = "";
    public const string List = "";
    public const string Tag = "";
    public const string Document = "";
}

public sealed class NavIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => (value as string) switch
    {
        "dashboard" => Glyph.Home,
        "scan" => Glyph.Search,
        "protections" => Glyph.Shield,
        "quarantine" => Glyph.Package,
        "check" => Glyph.Diagnostic,
        "history" => Glyph.History,
        "settings" => Glyph.Settings,
        _ => "",
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
