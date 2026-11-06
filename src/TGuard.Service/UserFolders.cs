namespace TGuard.Service;

public static class UserFolders
{
    private static readonly HashSet<string> SkipProfiles = new(StringComparer.OrdinalIgnoreCase)
        { "Public", "Default", "Default User", "All Users", "WDAGUtilityAccount", "defaultuser0" };

    public static IEnumerable<string> Profiles()
    {
        var usersRoot = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users");
        if (!Directory.Exists(usersRoot)) yield break;
        foreach (var d in Directory.EnumerateDirectories(usersRoot))
        {
            var name = Path.GetFileName(d);
            if (SkipProfiles.Contains(name)) continue;
            if (!Directory.Exists(Path.Combine(d, "AppData"))) continue;
            yield return d;
        }
    }

    public static List<string> Resolve(IEnumerable<string> patterns)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var profiles = Profiles().ToList();
        foreach (var raw in patterns)
        {
            var p = raw.Trim();
            if (p.Length == 0) continue;
            var perUser = p.Contains("%USERPROFILE%", StringComparison.OrdinalIgnoreCase)
                       || p.Contains("%TEMP%", StringComparison.OrdinalIgnoreCase)
                       || p.Contains("%APPDATA%", StringComparison.OrdinalIgnoreCase)
                       || p.Contains("%LOCALAPPDATA%", StringComparison.OrdinalIgnoreCase);
            if (!perUser) { var e = Environment.ExpandEnvironmentVariables(p); if (Directory.Exists(e)) result.Add(e); continue; }
            foreach (var prof in profiles)
            {
                var x = Replace(p, "%USERPROFILE%", prof);
                x = Replace(x, "%TEMP%", Path.Combine(prof, "AppData", "Local", "Temp"));
                x = Replace(x, "%LOCALAPPDATA%", Path.Combine(prof, "AppData", "Local"));
                x = Replace(x, "%APPDATA%", Path.Combine(prof, "AppData", "Roaming"));
                x = Environment.ExpandEnvironmentVariables(x);
                if (Directory.Exists(x)) result.Add(x);
            }
        }
        return result.ToList();
    }

    public static List<(string Path, int Depth)> QuickScanTargets()
    {
        var deep = Resolve(new[]
        {
            "%USERPROFILE%\\Downloads", "%USERPROFILE%\\Desktop", "%TEMP%",
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        });
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (Directory.Exists(common)) deep.Add(common);
        var pub = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users", "Public");
        if (Directory.Exists(pub)) deep.Add(pub);
        var list = deep.Select(d => (d, 6)).ToList();
        list.AddRange(Resolve(new[] { "%APPDATA%", "%LOCALAPPDATA%" }).Select(d => (d, 1)));
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (Directory.Exists(programData)) list.Add((programData, 1));
        return list;
    }

    public static List<(string Path, int Depth)> FullScanTargets() =>
        DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable)
                 .Select(d => (d.RootDirectory.FullName, int.MaxValue)).ToList();

    private static string Replace(string s, string token, string value) =>
        s.Replace(token, value, StringComparison.OrdinalIgnoreCase);
}
