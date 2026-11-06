# TGuard

A free, open-source antivirus for Windows, built in Portugal.

TGuard runs alongside Microsoft Defender as a second layer. It focuses on the stuff that
actually catches people out: fake invoices and delivery notices, phishing pages, malicious
email attachments, Office macros, script droppers, infected USB sticks and ransomware.

> TGuard is still young. Keep Microsoft Defender turned on.

## What it does

**Real-time protection.** A Windows service watches Downloads, Desktop, Documents and the temp
folders for every user on the PC, plus any USB drive while it's plugged in. New files are
scanned as soon as they finish writing, and anything malicious is moved to an encrypted
quarantine.

**Execution blocking.** Every process that starts is checked: the executable, its command
line (Base64-encoded PowerShell is decoded first) and any script it was told to run.
If it's malicious the process is terminated and the file quarantined.

**USB drives.** Removable drives are scanned when plugged in, including `autorun.inf` tricks.

**Scanning engine.** Written from scratch, no third-party AV engine:

- SHA-256 signatures, updated from MalwareBazaar
- YARA-style rules in plain JSON — see [`default.rules.json`](src/TGuard.Core/Resources/default.rules.json)
- file type detection by content, so a `.pdf` that is really an `.exe` gets caught
- a PE parser for Windows executables (packers, W+X sections, injection imports)
- Office macros, including decompressing the VBA source (MS-OVBA)
- PDF, HTML, JavaScript/VBScript, `.lnk` shortcuts, nested ZIPs and password-protected ZIPs
- Authenticode verification, so signed software from known vendors doesn't get flagged
- Mark-of-the-Web: where a file was downloaded from is part of the verdict
- phishing link analysis tuned for Portuguese banks and services (CGD, Millennium, MB WAY, CTT, Finanças…)

Every file gets a score from 0 to 100. 40 and up is suspicious, 80 and up is malicious.

**PC security check.** Defender status, firewall, Windows Update, UAC, SMBv1, Remote Desktop,
BitLocker, Wi-Fi security and suspicious startup entries.

**Updates.** Signatures and malicious URL lists are refreshed every 6 hours.

Still to come: email protection (Gmail, Outlook, IMAP), anti-ransomware decoy files,
a browser extension and an installer.

## Building

You need the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
dotnet build TGuard.sln -c Release
dotnet run --project tests/TGuard.Tests
dotnet run --project src/TGuard.Cli -- scan C:\Users\me\Downloads
dotnet run --project src/TGuard.Cli -- check
```

Every push is built and tested on Windows by GitHub Actions. The integration tests start the
service, drop harmless test samples and check that they get caught, quarantined or killed.
Builds are available from the Actions tab; `scripts/Install-TGuard.ps1` installs one for testing.

## Layout

```
src/TGuard.Core      scanning engine (no external dependencies)
src/TGuard.Service   Windows service: real-time, execution blocking, USB, updates
src/TGuard.App       desktop app (WPF), Portuguese and English
src/TGuard.Cli       command line
tests/TGuard.Tests   engine tests
```

## Privacy

Everything is scanned locally. Nothing leaves your PC unless you turn on anonymous threat
sharing (off by default), and even then only hashes and URLs are sent, never your files.

## Contributing

New detection rules are very welcome. A rule is a few lines of JSON; open a pull request
with a short description and, if you can, a SHA-256 of a sample it catches.

## License

[MIT](LICENSE) © Luís Tavares — [luis-tavares.pt](https://luis-tavares.pt)

Fonts: [Bagel Fat One](https://fonts.google.com/specimen/Bagel+Fat+One) and
[Outfit](https://fonts.google.com/specimen/Outfit), SIL Open Font License.
