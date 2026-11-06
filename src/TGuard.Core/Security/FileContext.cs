using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace TGuard.Core.Security;

public enum SignatureState { NotChecked, Unsigned, Valid, Invalid, Untrusted }

public sealed record SignatureInfo(SignatureState State, string? Signer = null);

public sealed record WebOrigin(int ZoneId, string? HostUrl, string? ReferrerUrl)
{
    public bool FromInternet => ZoneId >= 3;
}

public static class FileContext
{
    public static WebOrigin? ReadWebOrigin(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            // File.Exists() returns false for alternate data streams, so just try to read it
            return ParseZoneIdentifier(File.ReadAllText(path + ":Zone.Identifier"));
        }
        catch (Exception) { return null; }
    }

    public static WebOrigin ParseZoneIdentifier(string content)
    {
        int zone = 0; string? host = null, referrer = null;
        foreach (var line in content.Split('\n'))
        {
            var i = line.IndexOf('=');
            if (i <= 0) continue;
            var k = line[..i].Trim();
            var v = line[(i + 1)..].Trim();
            if (k.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)) int.TryParse(v, out zone);
            else if (k.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) host = v;
            else if (k.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) referrer = v;
        }
        return new WebOrigin(zone, host, referrer);
    }

    public static SignatureInfo VerifySignature(string path)
    {
        if (!OperatingSystem.IsWindows()) return new(SignatureState.NotChecked);
        try
        {
            var result = WinTrust.Verify(path);
            string? signer = null;
            if (result != WinTrust.TRUST_E_NOSIGNATURE && result != WinTrust.TRUST_E_SUBJECT_FORM_UNKNOWN)
            {
                try
                {
#pragma warning disable SYSLIB0057
                    using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
                    signer = cert.GetNameInfo(X509NameType.SimpleName, false);
                }
                catch (Exception) { }
            }
            return result switch
            {
                0 => new(SignatureState.Valid, signer),
                WinTrust.TRUST_E_NOSIGNATURE or WinTrust.TRUST_E_SUBJECT_FORM_UNKNOWN or WinTrust.TRUST_E_PROVIDER_UNKNOWN => new(SignatureState.Unsigned),
                WinTrust.TRUST_E_BAD_DIGEST or WinTrust.TRUST_E_CERT_SIGNATURE => new(SignatureState.Invalid, signer),
                _ => new(SignatureState.Untrusted, signer),
            };
        }
        catch (Exception) { return new(SignatureState.NotChecked); }
    }

    private static class WinTrust
    {
        public const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        public const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        public const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
        public const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
        public const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004);

        private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;          // 2 = no UI
            public uint fdwRevocationChecks; // 0 = none, don't hit the network
            public uint dwUnionChoice;       // 1 = file
            public IntPtr pFile;
            public uint dwStateAction;       // 1 = verify, 2 = close
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;         // 0x1000 = cache-only revocation
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        public static int Verify(string path)
        {
            var pathPtr = Marshal.StringToHGlobalUni(path);
            var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pathPtr };
            var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,
                fdwRevocationChecks = 0,
                dwUnionChoice = 1,
                pFile = filePtr,
                dwStateAction = 1,
                dwProvFlags = 0x00001000,
            };
            var action = ActionGenericVerifyV2;
            try
            {
                return WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            }
            finally
            {
                data.dwStateAction = 2;
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                Marshal.FreeHGlobal(filePtr);
                Marshal.FreeHGlobal(pathPtr);
            }
        }
    }
}
