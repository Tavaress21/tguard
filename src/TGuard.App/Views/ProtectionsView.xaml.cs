using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Controls;
using TGuard.App.Services;

namespace TGuard.App.Views;

public partial class ProtectionsView : UserControl, IRefreshable
{
    public ProtectionsView() => InitializeComponent();

    public async Task RefreshAsync()
    {
        var st = await App.Backend.GetStatusAsync();
        var settings = await App.Backend.GetSettingsAsync();

        ModuleRow Active(string key, string glyph, bool on, string? desc = null) => new()
        {
            Title = S.T(key), Description = desc ?? S.T(key + ".sub"), Glyph = glyph,
            Status = on ? S.T("active") : S.T("inactive"),
            StatusBackground = Palette.B(on ? "GoodSoft" : "BadSoft"),
            StatusForeground = Palette.B(on ? "Good" : "Bad"),
        };
        ModuleRow Soon(string key, string glyph) => new()
        {
            Title = S.T(key), Description = S.T(key + ".sub"), Glyph = glyph, Status = S.T("soon"),
            StatusBackground = Palette.B("WarnSoft"), StatusForeground = Palette.B("Warn"),
        };

        var svc = App.Backend.ServiceAvailable;
        ModuleRow Needs(string key, string glyph, string? desc = null) => new()
        {
            Title = S.T(key), Description = desc ?? S.T(key + ".sub"), Glyph = glyph, Status = S.T("prot.needsservice"),
            StatusBackground = Palette.B("InfoSoft"), StatusForeground = Palette.B("Info"),
        };
        Modules.ItemsSource = new List<ModuleRow>
        {
            svc ? Active("prot.realtime", Glyph.Shield, st.RealtimeEnabled) : Needs("prot.realtime", Glyph.Shield),
            svc ? Active("prot.process", Glyph.Lightning, st.ProcessGuardActive) : Needs("prot.process", Glyph.Lightning),
            svc ? Active("prot.usb", Glyph.Usb, st.UsbProtection, S.T("prot.usb.active.sub")) : Needs("prot.usb", Glyph.Usb, S.T("prot.usb.active.sub")),
            Active("prot.updates", Glyph.Recent, st.AutoUpdate),
            svc ? Active("prot.scheduled", Glyph.Calendar, settings.ScheduledQuickScan, S.F("prot.scheduled.sub", settings.ScheduledQuickScanHour))
                : Needs("prot.scheduled", Glyph.Calendar, S.F("prot.scheduled.sub", settings.ScheduledQuickScanHour)),
            Soon("prot.email", Glyph.Mail),
            Soon("prot.ransom", Glyph.Lock),
            Soon("prot.web", Glyph.Globe),
        };
    }
}
