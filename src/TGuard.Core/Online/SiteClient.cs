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

    private static readonly Lazy<HttpClient> Shared = new(() =>
        CreateClient(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(10) }));

    private readonly HttpClient _http;
    private readonly Uri _base;

    public SiteClient(TGuardSettings settings, HttpMessageHandler? handler = null)
    {
        _base = Updater.UpdateBase(settings.SiteUrl);
        _http = handler is null ? Shared.Value : CreateClient(handler);
    }

    private static HttpClient CreateClient(HttpMessageHandler handler)
    {
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("TGuard", Version));
        return http;
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

    public async Task<SyncResponse> SyncAsync(SyncRequest request, CancellationToken ct = default)
    {
        using var resp = await PostAsync("api/tguard/sync", request, ct);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        var result = new SyncResponse();
        if (root.TryGetProperty("account", out var account))
        {
            if (account.ValueKind == JsonValueKind.False) result.AccountRevoked = true;
            else if (account.ValueKind == JsonValueKind.Object && account.TryGetProperty("name", out var name)) result.AccountName = name.GetString();
        }
        if (root.TryGetProperty("commands", out var cmds) && cmds.ValueKind == JsonValueKind.Array)
            foreach (var c in cmds.EnumerateArray())
                if (c.TryGetProperty("id", out var id) && id.TryGetInt64(out var cid) && c.TryGetProperty("type", out var type))
                {
                    var command = new RemoteCommand { Id = cid, Type = type.GetString() ?? "" };
                    if (c.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Object)
                        foreach (var a in args.EnumerateObject())
                            command.Args[a.Name] = a.Value.ValueKind == JsonValueKind.String ? a.Value.GetString() ?? "" : a.Value.GetRawText();
                    result.Commands.Add(command);
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
