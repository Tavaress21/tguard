using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace TGuard.Core.Security;

public enum SignatureState { NotChecked, Unsigned, Valid, Invalid, Untrusted }

public sealed record SignatureInfo(SignatureState State, string? Signer = null, bool ViaCatalog = false)
{
    public bool IsMicrosoft => State == SignatureState.Valid && Signer is not null &&
                               Signer.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);
}

public sealed record WebOrigin(int ZoneId, string? HostUrl, string? ReferrerUrl)
{
    public bool FromInternet => ZoneId >= 3;
}

public static class FileContext
{
    private static readonly string[] ProtectedRoots = BuildProtectedRoots();
    private static readonly string[] WritableInside = { "\\Temp\\", "\\Tasks\\", "\\spool\\", "\\Tracing\\", "\\Debug\\", "\\Registration\\CRMLog\\" };

    public static bool IsProtectedLocation(string path)
    {
        if (ProtectedRoots.Length == 0 || string.IsNullOrEmpty(path)) return false;
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
        if (!ProtectedRoots.Any(root => full.StartsWith(root, StringComparison.OrdinalIgnoreCase))) return false;
        return !WritableInside.Any(part => full.Contains(part, StringComparison.OrdinalIgnoreCase));
    }

    private static string[] BuildProtectedRoots()
    {
        if (!OperatingSystem.IsWindows()) return Array.Empty<string>();
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("ProgramW6432"),
            string.IsNullOrEmpty(windows) ? null : Path.Combine(windows, "System32"),
            string.IsNullOrEmpty(windows) ? null : Path.Combine(windows, "SysWOW64"),
            string.IsNullOrEmpty(windows) ? null : Path.Combine(windows, "WinSxS"),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
        };
        return roots.Where(r => !string.IsNullOrEmpty(r)).Select(r => r!.TrimEnd('\\') + "\\").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static WebOrigin? ReadWebOrigin(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
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
            if (result is WinTrust.TRUST_E_NOSIGNATURE or WinTrust.TRUST_E_SUBJECT_FORM_UNKNOWN)
            {
                var cat = Catalog.Verify(path);
                if (cat is not null) return cat;
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

    private static class Catalog
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, Microsoft.Win32.SafeHandles.SafeFileHandle file, ref uint hashSize, byte[]? hash, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags, IntPtr prevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CATALOG_INFO info, uint flags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

        [DllImport("wintrust.dll")]
        private static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

        public static SignatureInfo? Verify(string path)
        {
            foreach (var algorithm in new[] { "SHA256", "SHA1" })
            {
                if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
                try
                {
                    byte[] hash;
                    using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        uint size = 0;
                        CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle, ref size, null, 0);
                        if (size == 0) continue;
                        hash = new byte[size];
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle, ref size, hash, 0)) continue;
                    }
                    var catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, (uint)hash.Length, 0, IntPtr.Zero);
                    if (catInfo == IntPtr.Zero) continue;
                    try
                    {
                        var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                        if (!CryptCATCatalogInfoFromContext(catInfo, ref info, 0)) continue;
                        var result = WinTrust.VerifyCatalogMember(info.wszCatalogFile, path, Convert.ToHexString(hash), admin);
                        string? signer = null;
                        try
                        {
#pragma warning disable SYSLIB0057
                            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(info.wszCatalogFile));
#pragma warning restore SYSLIB0057
                            signer = cert.GetNameInfo(X509NameType.SimpleName, false);
                        }
                        catch (Exception) { }
                        return result == 0
                            ? new SignatureInfo(SignatureState.Valid, signer, ViaCatalog: true)
                            : new SignatureInfo(SignatureState.Invalid, signer, ViaCatalog: true);
                    }
                    finally { CryptCATAdminReleaseCatalogContext(admin, catInfo, 0); }
                }
                catch (Exception) { }
                finally { CryptCATAdminReleaseContext(admin, 0); }
            }
            return null;
        }
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
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        public static int VerifyCatalogMember(string catalogPath, string filePath, string memberTag, IntPtr catAdmin)
        {
            var catPtr = Marshal.StringToHGlobalUni(catalogPath);
            var tagPtr = Marshal.StringToHGlobalUni(memberTag);
            var filePtr = Marshal.StringToHGlobalUni(filePath);
            var info = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = filePtr,
                hCatAdmin = catAdmin,
            };
            var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(info, infoPtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,
                fdwRevocationChecks = 0,
                dwUnionChoice = 2,
                pFile = infoPtr,
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
                Marshal.FreeHGlobal(infoPtr);
                Marshal.FreeHGlobal(catPtr);
                Marshal.FreeHGlobal(tagPtr);
                Marshal.FreeHGlobal(filePtr);
            }
        }

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
