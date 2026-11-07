using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using TGuard.App.Views;
using TGuard.Core;
using TGuard.Core.Ipc;
using TGuard.Core.Storage;

namespace TGuard.App.Services;

public static class SelfTest
{
    public static async Task<int> RunAsync(string outDir)
    {
        try
        {
            Directory.CreateDirectory(outDir);
            var bindingErrors = new ErrorCollector();
            System.Diagnostics.PresentationTraceSources.Refresh();
            System.Diagnostics.PresentationTraceSources.DataBindingSource.Listeners.Add(bindingErrors);
            System.Diagnostics.PresentationTraceSources.DataBindingSource.Switch.Level = System.Diagnostics.SourceLevels.Warning;
            TGuardPaths.Root = Path.Combine(Path.GetTempPath(), "tguard-selftest");
            if (Directory.Exists(TGuardPaths.Root)) Directory.Delete(TGuardPaths.Root, true);
            TGuardPaths.Ensure();
            Seed();

            App.Backend = new Backend();

            var win = new MainWindow { Left = -20000, Top = 0, ShowActivated = false, ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual };
            win.Show();

            foreach (var key in new[] { "dashboard", "scan", "protections", "quarantine", "check", "history", "help", "settings" })
            {
                win.Navigate(key);
                var view = (FrameworkElement)win.Host.Content;
                if (view is IRefreshable r) await r.RefreshAsync();
                if (view is ScanView sv) sv.Show(SampleScan());
                if (view is CheckView cv) cv.Show(await App.Backend.CheckAsync());
                if (view is ChatView chat) chat.Preview(SampleChat());
                await Task.Delay(300);
                win.UpdateLayout();
                Save(win, Path.Combine(outDir, $"{key}.png"));
                Console.WriteLine($"ok {key}");
            }
            App.Backend.Showcase = new ServiceStatus
            {
                Version = typeof(SelfTest).Assembly.GetName().Version?.ToString(3) ?? "",
                RealtimeEnabled = true, ProcessGuardActive = true, UsbProtection = true, AutoUpdate = true,
                BadUrls = 48213, WatchedFolders = 6, Signatures = 312874, Rules = 22, QuarantineCount = 2, ThreatsLast30Days = 3,
                LastScan = DateTimeOffset.Now.AddHours(-3), LastUpdate = DateTimeOffset.Now.AddMinutes(-40),
            };
            win.Navigate("dashboard");
            if (win.Host.Content is IRefreshable showcase) await showcase.RefreshAsync();
            await Task.Delay(300);
            win.UpdateLayout();
            Save(win, Path.Combine(outDir, "showcase.png"));
            App.Backend.Showcase = null;

            var dlg = Dialog.Preview(S.T("q.restore.title"), S.T("q.restore.confirm") + "\n\n" + S.T("q.restore.note"), S.T("q.restore"), DialogKind.Warning);
            dlg.Left = -20000; dlg.ShowActivated = false; dlg.WindowStartupLocation = WindowStartupLocation.Manual;
            dlg.Show();
            await Task.Delay(200);
            Save(dlg, Path.Combine(outDir, "dialog.png"));
            dlg.Close();

            win.ReallyClose = true;
            win.Close();

            var errors = bindingErrors.Messages.Where(m => m.Contains("Error", StringComparison.Ordinal)).ToList();
            if (errors.Count > 0)
            {
                File.WriteAllLines(Path.Combine(outDir, "binding-errors.txt"), errors);
                Console.Error.WriteLine(string.Join("\n", errors));
                return 2;
            }
            return 0;
        }
        catch (Exception ex)
        {
            File.WriteAllText(Path.Combine(outDir, "error.txt"), ex.ToString());
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private sealed class ErrorCollector : System.Diagnostics.TraceListener
    {
        public List<string> Messages { get; } = new();
        private readonly StringBuilder _line = new();
        public override void Write(string? message) => _line.Append(message);
        public override void WriteLine(string? message)
        {
            _line.Append(message);
            lock (Messages) Messages.Add(_line.ToString());
            _line.Clear();
        }
    }

    private static TGuard.Core.Online.ChatState SampleChat() => new()
    {
        Online = true,
        Active = true,
        Status = "open",
        Agent = "Luís",
        Messages = new()
        {
            new() { Id = 1, Body = Loc.Pick("O PC está muito lento desde ontem e aparecem janelas estranhas no browser.", "The PC has been very slow since yesterday and strange windows pop up in the browser."), CreatedAt = DateTimeOffset.Now.AddMinutes(-6) },
            new() { Id = 2, FromAdmin = true, AdminName = "Luís", Body = Loc.Pick("Olá! Vamos ver isso. Podes carregar em \"Pedir assistência remota\"?", "Hi! Let's take a look. Can you press \"Ask for remote assistance\"?"), CreatedAt = DateTimeOffset.Now.AddMinutes(-5) },
            new() { Id = 3, Body = Loc.Pick("Pedido de assistência remota", "Remote assistance request"), CreatedAt = DateTimeOffset.Now.AddMinutes(-4) },
            new() { Id = 4, FromAdmin = true, AdminName = "Luís", Body = Loc.Pick("Abre a Assistência Rápida e escreve o código 482 913.", "Open Quick Assist and type the code 482 913."), CreatedAt = DateTimeOffset.Now.AddMinutes(-3) },
        },
    };

    private static void Save(Window win, string path)
    {
        var root = (FrameworkElement)win.Content;
        var w = (int)Math.Ceiling(root.ActualWidth);
        var h = (int)Math.Ceiling(root.ActualHeight);
        var bmp = new RenderTargetBitmap(Math.Max(w, 1), Math.Max(h, 1), 96, 96, PixelFormats.Pbgra32);
        bmp.Render(root);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        enc.Save(fs);
    }

    private static void Seed()
    {
        var events = new EventStore();
        var q = new Quarantine();
        var eicar = Encoding.ASCII.GetBytes(string.Concat("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"));
        q.Store(eicar, @"C:\Users\Luis\Downloads\fatura_CTT_2026.pdf.exe", "TGuard.Heur.Pe", new[] { "Extensão dupla enganadora ('.pdf.exe') (+50)", "Programa sem assinatura digital (+10)" });
        q.Store(eicar, @"C:\Users\Luis\Downloads\Encomenda retida.zip", "TGuard.HTML_Phishing_Form", new[] { "Anexo HTML com formulário de login que envia dados para fora (+55)" });
        new TrustStore().Add("4f7a1c0e9b2d3a6f8e5c7b1d0a9f3e2c4b6d8a0f1e3c5b7d9f2a4c6e8b0d1f3a", @"C:\Users\Luis\Downloads\ferramenta_rede.exe");
        events.Add(new SecurityEvent { Date = DateTimeOffset.Now.AddMinutes(-12), Source = "realtime", Target = @"C:\Users\Luis\Downloads\fatura_CTT_2026.pdf.exe", Verdict = "malicious", Score = 95, Headline = "TGuard.Heur.Pe", Action = "Movido para a quarentena", Reasons = new() { "Extensão dupla enganadora ('.pdf.exe') (+50)" } });
        events.Add(new SecurityEvent { Date = DateTimeOffset.Now.AddHours(-3), Source = "scan", Target = @"C:\Users\Luis\Desktop\macro_orcamento.docm", Verdict = "suspicious", Score = 50, Headline = "Documento contém macros VBA", Reasons = new() { "Documento contém macros VBA (+25)" } });
        events.Add(new SecurityEvent { Date = DateTimeOffset.Now.AddDays(-2), Source = "scan", Target = @"C:\Users\Luis\Downloads\Encomenda retida.zip", Verdict = "malicious", Score = 88, Headline = "TGuard.HTML_Phishing_Form", Action = "Movido para a quarentena" });
    }

    private static ScanProgress SampleScan() => new()
    {
        Id = "demo", Type = "quick", Running = true, FilesScanned = 4821, Threats = 1, Started = DateTimeOffset.Now.AddMinutes(-2),
        CurrentFile = @"C:\Users\Luis\AppData\Local\Temp\setup_4f2a\installer.msi",
        Found = new List<ThreatInfo>
        {
            new() { Path = @"C:\Users\Luis\Downloads\MBWAY_reembolso.js", Name = "TGuard.Obfuscated_Script", Verdict = "malicious", Score = 90,
                    Action = "Movido para a quarentena", Reasons = new() { "JavaScript/VBScript com ofuscação e execução de comandos (+45)", "Contém um bloco Base64 muito longo (+15)" } },
        },
    };
}
