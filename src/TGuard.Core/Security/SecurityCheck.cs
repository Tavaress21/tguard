using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

namespace TGuard.Core.Security;

public enum CheckStatus { Ok, Info, Warning, Critical }

public sealed record CheckItem(string Id, string Title, CheckStatus Status, string Detail, string Fix = "");

public static class SecurityCheck
{
    // One PowerShell call that collects everything as JSON (much faster than several processes).
    private const string Script = @"
$ErrorActionPreference='SilentlyContinue'
$r=@{}
$mp=Get-MpComputerStatus
if($mp){$r.defRt=$mp.RealTimeProtectionEnabled;$r.defAv=$mp.AntivirusEnabled;$r.defSigAge=$mp.AntivirusSignatureAge;$r.defTamper=$mp.IsTamperProtected}
$r.fw=@(Get-NetFirewallProfile | ForEach-Object { @{n=$_.Name;e=[bool]$_.Enabled} })
$hf=Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if($hf){$r.lastUpdate=$hf.InstalledOn.ToString('o')}
$smb=Get-SmbServerConfiguration
if($smb){$r.smb1=$smb.EnableSMB1Protocol}
$bl=Get-BitLockerVolume -MountPoint $env:SystemDrive
if($bl){$r.bitlocker=[string]$bl.ProtectionStatus}
$ssid=(netsh wlan show interfaces | Select-String '^\s+SSID\s+:\s(.+)$' | Select-Object -First 1)
if($ssid){$s=$ssid.Matches[0].Groups[1].Value.Trim();$r.wifi=$s
 $p=netsh wlan show profile name=""$s"" key=clear
 $auth=($p | Select-String 'Authentication|Autentica' | Select-Object -First 1); if($auth){$r.wifiAuth=($auth.ToString() -split ':',2)[1].Trim()}
 $k=($p | Select-String 'Key Content|Conte.do da Chave|Conte.do da chave' | Select-Object -First 1); if($k){$r.wifiKeyLen=(($k.ToString() -split ':',2)[1].Trim()).Length}}
$r | ConvertTo-Json -Depth 4 -Compress";

    public static List<CheckItem> Run()
    {
        var items = new List<CheckItem>();
        if (!OperatingSystem.IsWindows())
        {
            items.Add(new("os", T("Sistema operativo", "Operating system"), CheckStatus.Info, T("A verificação do PC só está disponível no Windows.", "PC check is only available on Windows.")));
            return items;
        }
        var ps = RunPowerShell(Script);
        JsonElement j = default;
        var hasJson = false;
        try { if (ps is not null) { j = JsonDocument.Parse(ps).RootElement; hasJson = true; } } catch (JsonException) { }

        bool? B(string n) => hasJson && j.TryGetProperty(n, out var v) && (v.ValueKind is JsonValueKind.True or JsonValueKind.False) ? v.GetBoolean() : null;
        string? S(string n) => hasJson && j.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        int? I(string n) => hasJson && j.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;

        // Microsoft Defender
        var rt = B("defRt");
        items.Add(rt switch
        {
            true => new("defender", "Microsoft Defender", CheckStatus.Ok, T("Proteção em tempo real ligada. O TGuard trabalha em conjunto com o Defender.", "Real-time protection on. TGuard works together with Defender.")),
            false => new("defender", "Microsoft Defender", CheckStatus.Critical, T("A proteção em tempo real do Defender está desligada.", "Defender real-time protection is off."),
                T("Abre Segurança do Windows → Proteção contra vírus e ameaças e liga a proteção em tempo real.", "Open Windows Security → Virus & threat protection and turn on real-time protection.")),
            _ => new("defender", "Microsoft Defender", CheckStatus.Info, T("Não foi possível ler o estado (pode haver outro antivírus instalado).", "Could not read status (another antivirus may be installed).")),
        });
        if (I("defSigAge") is int age && age > 7)
            items.Add(new("defsig", T("Assinaturas do Defender", "Defender signatures"), CheckStatus.Warning, T($"Desatualizadas há {age} dias.", $"Out of date for {age} days."),
                T("Segurança do Windows → Atualizações de proteção → Verificar atualizações.", "Windows Security → Protection updates → Check for updates.")));
        if (B("defTamper") == false)
            items.Add(new("tamper", T("Proteção contra adulteração", "Tamper protection"), CheckStatus.Warning,
                T("Desligada: malware pode desativar o Defender.", "Off: malware can disable Defender."),
                T("Segurança do Windows → Definições de proteção → Proteção contra adulteração.", "Windows Security → Manage settings → Tamper Protection.")));

        // Firewall
        if (hasJson && j.TryGetProperty("fw", out var fw) && fw.ValueKind == JsonValueKind.Array)
        {
            var off = fw.EnumerateArray().Where(p => p.TryGetProperty("e", out var e) && !e.GetBoolean())
                        .Select(p => p.GetProperty("n").GetString()).ToList();
            items.Add(off.Count == 0
                ? new("firewall", "Firewall", CheckStatus.Ok, T("Ligada em todos os perfis.", "On for all profiles."))
                : new("firewall", "Firewall", CheckStatus.Critical, T($"Desligada nos perfis: {string.Join(", ", off)}.", $"Off for profiles: {string.Join(", ", off)}."),
                    T("Segurança do Windows → Firewall e proteção de rede → ligar.", "Windows Security → Firewall & network protection → turn on.")));
        }

        // Windows Update
        if (S("lastUpdate") is string lu && DateTimeOffset.TryParse(lu, out var last))
        {
            var days = (int)(DateTimeOffset.Now - last).TotalDays;
            items.Add(days <= 45
                ? new("winupdate", "Windows Update", CheckStatus.Ok, T($"Última atualização há {days} dias.", $"Last update {days} days ago."))
                : new("winupdate", "Windows Update", CheckStatus.Warning, T($"Última atualização instalada há {days} dias.", $"Last update installed {days} days ago."),
                    T("Definições → Windows Update → Procurar atualizações.", "Settings → Windows Update → Check for updates.")));
        }

        // UAC
        var lua = ReadDword(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
        items.Add(lua == 0
            ? new("uac", T("Controlo de Conta de Utilizador (UAC)", "User Account Control (UAC)"), CheckStatus.Critical, T("Desativado: qualquer programa corre com poderes de administrador.", "Disabled: any program runs with administrator rights."),
                T("Painel de Controlo → Contas de Utilizador → Alterar definições do Controlo de Conta de Utilizador.", "Control Panel → User Accounts → Change User Account Control settings."))
            : new("uac", T("Controlo de Conta de Utilizador (UAC)", "User Account Control (UAC)"), CheckStatus.Ok, T("Ativo.", "Enabled.")));

        // Remote Desktop
        var denyRdp = ReadDword(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        if (denyRdp == 0)
            items.Add(new("rdp", T("Ambiente de Trabalho Remoto", "Remote Desktop"), CheckStatus.Warning,
                T("Ligado: se a porta 3389 estiver exposta à Internet é um alvo frequente de ataques.", "On: if port 3389 is exposed to the Internet it is a frequent attack target."),
                T("Desliga-o em Definições → Sistema → Ambiente de Trabalho Remoto se não o usares.", "Turn it off in Settings → System → Remote Desktop if you don't use it.")));

        // SMBv1
        if (B("smb1") == true)
            items.Add(new("smb1", "SMBv1", CheckStatus.Critical, T("Protocolo antigo ativo (usado pelo WannaCry).", "Legacy protocol enabled (used by WannaCry)."),
                T("PowerShell (admin): Set-SmbServerConfiguration -EnableSMB1Protocol $false", "PowerShell (admin): Set-SmbServerConfiguration -EnableSMB1Protocol $false")));

        // AutoRun
        var autorun = ReadDword(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
        items.Add(autorun is >= 0xFF
            ? new("autorun", T("Execução automática de pens/CDs", "AutoRun for USB/CD"), CheckStatus.Ok, T("Bloqueada.", "Blocked."))
            : new("autorun", T("Execução automática de pens/CDs", "AutoRun for USB/CD"), CheckStatus.Warning, T("Não está totalmente bloqueada.", "Not fully blocked."),
                T("O TGuard pode bloquear isto no separador Pens USB.", "TGuard can block this in the USB tab.")));

        // BitLocker
        if (S("bitlocker") is string bl)
            items.Add(bl == "On"
                ? new("bitlocker", "BitLocker", CheckStatus.Ok, T("Disco do sistema cifrado.", "System drive encrypted."))
                : new("bitlocker", "BitLocker", CheckStatus.Info, T("Disco do sistema não cifrado: se o PC for roubado, os dados ficam acessíveis.", "System drive not encrypted: if stolen, data is readable.")));

        // Wi-Fi
        if (S("wifi") is string ssid)
        {
            var auth = S("wifiAuth") ?? "";
            var keyLen = I("wifiKeyLen");
            if (auth.Contains("Open", StringComparison.OrdinalIgnoreCase) || auth.Contains("Abert", StringComparison.OrdinalIgnoreCase) || auth.Contains("WEP", StringComparison.OrdinalIgnoreCase))
                items.Add(new("wifi", $"Wi-Fi ({ssid})", CheckStatus.Critical, T($"Rede sem proteção adequada ({auth}).", $"Network without proper security ({auth})."), T("Usa WPA2 ou WPA3 no router.", "Use WPA2 or WPA3 on the router.")));
            else if (keyLen is int kl && kl < 12)
                items.Add(new("wifi", $"Wi-Fi ({ssid})", CheckStatus.Warning, T($"Password curta ({kl} carateres).", $"Short password ({kl} characters)."), T("Usa pelo menos 12 carateres na password do Wi-Fi.", "Use at least 12 characters for the Wi-Fi password.")));
            else
                items.Add(new("wifi", $"Wi-Fi ({ssid})", CheckStatus.Ok, T($"Protegida ({auth}).", $"Protected ({auth}).")));
        }

        // Startup entries from suspicious locations
        foreach (var (name, cmd) in StartupEntries())
        {
            var c = cmd.ToLowerInvariant();
            if (c.Contains(@"\temp\") || c.Contains(@"\appdata\local\temp") || c.Contains("powershell") && c.Contains("-enc")
                || c.Contains("mshta") || c.Contains("wscript") || c.Contains(@"\users\public\"))
                items.Add(new("startup:" + name, T($"Arranque: {name}", $"Startup: {name}"), CheckStatus.Warning,
                    T($"Programa no arranque a partir de local suspeito: {cmd}", $"Startup program from suspicious location: {cmd}"),
                    T("Se não o reconheces, desativa-o no Gestor de Tarefas → Arranque.", "If you don't recognise it, disable it in Task Manager → Startup.")));
        }
        return items;
    }

    [SupportedOSPlatform("windows")]
    public static IEnumerable<(string Name, string Command)> StartupEntries()
    {
        const string run = @"Software\Microsoft\Windows\CurrentVersion\Run";
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            using var k = root.OpenSubKey(run);
            if (k is null) continue;
            foreach (var n in k.GetValueNames())
                yield return (n, k.GetValue(n)?.ToString() ?? "");
        }
    }

    [SupportedOSPlatform("windows")]
    private static int? ReadDword(RegistryKey root, string path, string name)
    {
        try { using var k = root.OpenSubKey(path); return k?.GetValue(name) is int v ? v : null; }
        catch (Exception) { return null; }
    }

    private static string? RunPowerShell(string script)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -")
            {
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            p.StandardInput.Write(script);
            p.StandardInput.Close();
            var output = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(60_000)) { p.Kill(true); return null; }
            return output.Result.Trim();
        }
        catch (Exception) { return null; }
    }

    private static string T(string pt, string en) => Loc.Pick(pt, en);
}
