using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TGuard.Service;

internal static class ClientVerifier
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    private static readonly string InstallRoot =
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..")).TrimEnd('\\') + "\\";

    public static bool IsTrustedClient(NamedPipeServerStream pipe, out string who)
    {
        who = "?";
        try
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid)) return false;
            using var p = Process.GetProcessById((int)pid);
            var exe = p.MainModule?.FileName ?? "";
            who = $"{exe} (pid {pid})";
            return exe.StartsWith(InstallRoot, StringComparison.OrdinalIgnoreCase)
                   && Path.GetFileName(exe).Equals("TGuard.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception) { return false; }
    }
}
