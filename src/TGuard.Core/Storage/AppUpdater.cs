using System.Text.Json;
using TGuard.Core.Security;

namespace TGuard.Core.Storage;

public sealed class AppRelease
{
    public string Version { get; set; } = "";
    public string File { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public string Notes { get; set; } = "";
}

/// <summary>Checks the update server for a newer TGuard and downloads its installer.</summary>
public sealed class AppUpdater
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);
    private readonly Updater _http;

    public AppUpdater(HttpMessageHandler? handler = null) => _http = new Updater(handler);

    public static Version CurrentVersion =>
        typeof(AppUpdater).Assembly.GetName().Version is { } v ? new Version(v.Major, v.Minor, Math.Max(v.Build, 0)) : new Version(0, 0, 0);

    /// <summary>Returns the newer release, or null when up to date. Throws if the manifest is not authentic.</summary>
    public async Task<AppRelease?> CheckAsync(TGuardSettings settings, CancellationToken ct = default)
    {
        var baseUri = Updater.UpdateBase(settings.UpdateUrl);
        var json = await _http.GetBytesAsync(new Uri(baseUri, "app.json"), ct);
        var sig = await _http.GetBytesAsync(new Uri(baseUri, "app.json.sig"), ct);
        if (!UpdateSigning.Verify(json, sig, settings.ExtraUpdateKeys.Prepend(UpdateSigning.ReleaseKey)))
            throw new InvalidDataException("app.json signature is not valid");
        var release = JsonSerializer.Deserialize<AppRelease>(json, Web) ?? throw new InvalidDataException("empty app.json");
        if (!System.Version.TryParse(release.Version, out var v)) throw new InvalidDataException("bad version in app.json");
        if (release.File.Contains('/') || release.File.Contains('\\') || release.File.Contains(".."))
            throw new InvalidDataException("bad file name in app.json");
        return v > CurrentVersion ? release : null;
    }

    /// <summary>Downloads the installer and checks its hash against the signed manifest.</summary>
    public async Task<string> DownloadAsync(TGuardSettings settings, AppRelease release, string folder, CancellationToken ct = default)
    {
        var bytes = await _http.GetBytesAsync(new Uri(Updater.UpdateBase(settings.UpdateUrl), release.File), ct);
        if (!SignatureDatabase.Sha256Hex(bytes).Equals(release.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("installer hash does not match app.json");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, release.File);
        await File.WriteAllBytesAsync(path, bytes, ct);
        return path;
    }
}
