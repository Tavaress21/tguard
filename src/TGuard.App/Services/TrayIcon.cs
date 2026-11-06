using System;
using System.Windows;
using Forms = System.Windows.Forms;

namespace TGuard.App.Services;

public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private bool _shownBackgroundTip;

    public TrayIcon(Action open, Action quickScan, Action exit)
    {
        var stream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/tguard.ico"))?.Stream;
        _icon = new Forms.NotifyIcon
        {
            Icon = stream is null ? System.Drawing.SystemIcons.Shield : new System.Drawing.Icon(stream),
            Text = "TGuard",
            Visible = true,
        };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(S.T("tray.open"), null, (_, _) => open());
        menu.Items.Add(S.T("tray.quick"), null, (_, _) => quickScan());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(S.T("tray.exit"), null, (_, _) => exit());
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => open();
        _icon.BalloonTipClicked += (_, _) => open();
    }

    public void Notify(string title, string message, bool warning, bool onlyOnce = false)
    {
        if (onlyOnce)
        {
            if (_shownBackgroundTip) return;
            _shownBackgroundTip = true;
        }
        _icon.ShowBalloonTip(5000, title, message, warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
