using System.Security.Cryptography;

namespace TGuard.Core.Security;

/// <summary>
/// Everything downloaded from the update server is signed (ECDSA P-256, SHA-256).
/// Two separate keys: the release key signs new versions of TGuard and never leaves the
/// GitHub release workflow; the feeds key signs signature/URL lists and lives on the server.
/// A compromised web server can therefore publish bad lists at worst, never a fake TGuard.
/// </summary>
public static class UpdateSigning
{
    public const string ReleaseKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUlzrpT4EdnEduKocSoRoRn17Y3QrnxrxMhsCZUyQAdFtEJXdSskcBenKyS1Kkw7rsC/aQkUnyWch3l4sWstPiQ==";
    public const string FeedsKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOnT4E1OQKC+pM8t/XL6AhFCqGOA8GeZqHwfjFHxfZRJtP9BPrltnjNIIwzBS9dHesYV5h6omGLgjU4Qs2KuijQ==";

    public static bool Verify(byte[] data, byte[] signature, IEnumerable<string> publicKeys)
    {
        foreach (var key in publicKeys)
        {
            try
            {
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(Convert.FromBase64String(Strip(key)), out _);
                if (ec.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                    return true;
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException) { }
        }
        return false;
    }

    public static byte[] Sign(byte[] data, string privateKeyPem)
    {
        using var ec = ECDsa.Create();
        ec.ImportFromPem(privateKeyPem);
        return ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    private static string Strip(string pem) => string.Concat(pem
        .Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "")
        .Where(c => !char.IsWhiteSpace(c)));
}
