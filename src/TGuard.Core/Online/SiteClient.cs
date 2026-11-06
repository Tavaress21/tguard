using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using TGuard.Core.Storage;

namespace TGuard.Core.Online;

public sealed class SiteClient
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly Uri _base;

    public SiteClient(TGuardSettings settings, HttpMessageHandler? handler = null)
    {
        _base = Updater.UpdateBase(settings.SiteUrl);
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromSeconds(30);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("TGuard", Version));
    }

    public static string Version => typeof(SiteClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

    public static string Os
    {
        get
        {
            var v = Environment.OSVersion.Version;
            var name = OperatingSystem.IsWindows() ? (v.Build >= 22000 ? "Windows 11" : "Windows 10") : Environment.OSVersion.Platform.ToString();
            return $"{name} ({v.Build}, {(Environment.Is64BitOperatingSystem ? "64" : "32")} bits)";
        }
    }

    public async Task<PingResult> PingAsync(string installId, string? token, int signatures, CancellationToken ct = default)
    {
        using var resp = await PostAsync("api/tguard/ping",
            new { InstallId = installId, Version, Os, Signatures = signatures, Token = token }, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var result = new PingResult();
        if (doc.RootElement.TryGetProperty("account", out var acc))
        {
            if (acc.ValueKind == JsonValueKind.False) result.AccountRevoked = true;
            else if (acc.ValueKind == JsonValueKind.Object && acc.TryGetProperty("name", out var n)) result.AccountName = n.GetString();
        }
        return result;
    }

    public async Task<LinkStart> StartLinkAsync(string installId, CancellationToken ct = default)
    {
        using var resp = await PostAsync("api/tguard/ligar", new { InstallId = installId, Os }, ct);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadFromJsonAsync<LinkStart>(Json, ct) ?? throw new InvalidDataException("empty answer");
    }

    public async Task<LinkPoll> PollLinkAsync(string secret, CancellationToken ct = default)
    {
        using var resp = await PostAsync("api/tguard/ligar/estado", new { Secret = secret }, ct);
        if (resp.StatusCode == HttpStatusCode.Gone) return new LinkPoll { Expired = true };
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadFromJsonAsync<LinkPoll>(Json, ct) ?? new LinkPoll();
    }

    public async Task UnlinkAsync(string token, CancellationToken ct = default)
    {
        using var resp = await PostAsync("api/tguard/desligar", new { Token = token }, ct);
        resp.EnsureSuccessStatusCode();
    }

    public async Task<int> ReportAsync(string installId, string? token, ReportRequest report, CancellationToken ct = default)
    {
        using var resp = await PostAsync("api/tguard/denuncia", new
        {
            InstallId = installId,
            Token = token,
            report.Type,
            Value = Trim(report.Value, 2000),
            FileName = Trim(report.FileName, 255),
            Detection = Trim(report.Detection, 120),
            Details = Trim(report.Details, 5000),
            Version,
        }, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        return doc.RootElement.TryGetProperty("id", out var id) && id.TryGetInt32(out var n) ? n : 0;
    }

    public static string HelpUrl(TGuardSettings settings)
    {
        var subject = $"TGuard {Version}";
        var message = $"\n\n---\nTGuard {Version}\n{Os}";
        return new Uri(Updater.UpdateBase(settings.SiteUrl),
            $"area-cliente/tickets?novo=1&assunto={Uri.EscapeDataString(subject)}&mensagem={Uri.EscapeDataString(message)}").ToString();
    }

    public static string ReportUrl(TGuardSettings settings, string type = "scam") =>
        new Uri(Updater.UpdateBase(settings.SiteUrl), $"tguard/denunciar?tipo={Uri.EscapeDataString(type)}").ToString();

    public static string AccountUrl(TGuardSettings settings) =>
        new Uri(Updater.UpdateBase(settings.SiteUrl), "area-cliente/tguard").ToString();

    private Task<HttpResponseMessage> PostAsync(string path, object body, CancellationToken ct) =>
        _http.PostAsJsonAsync(new Uri(_base, path), body, Json, ct);

    private static string? Trim(string? s, int max) => s is null ? null : s.Length <= max ? s : s[..max];
}

public sealed class PingResult
{
    public string? AccountName { get; set; }
    public bool AccountRevoked { get; set; }
}

public sealed class LinkStart
{
    public string Code { get; set; } = "";
    public string Secret { get; set; } = "";
    public string Url { get; set; } = "";
    public int ExpiresIn { get; set; }
}

public sealed class LinkPoll
{
    public bool Linked { get; set; }
    public bool Expired { get; set; }
    public string? Token { get; set; }
    public LinkAccount? Account { get; set; }
}

public sealed class LinkAccount
{
    public string? Name { get; set; }
    public string? Email { get; set; }
}

public sealed class ReportRequest
{
    public string Type { get; set; } = "false_positive";
    public string? Value { get; set; }
    public string? FileName { get; set; }
    public string? Detection { get; set; }
    public string? Details { get; set; }
}

public sealed class AccountStatus
{
    public bool Linked { get; set; }
    public string? Name { get; set; }
    public string? Email { get; set; }
    public bool UsageStats { get; set; }
}
