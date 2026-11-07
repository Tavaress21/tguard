# TGuard

A free, open-source antivirus for Windows, made in Portugal.

TGuard runs alongside Microsoft Defender as a second layer. It is tuned for the things that
actually catch people out here: fake invoices and delivery notices, MB WAY and bank phishing,
malicious email attachments, Office macros, script droppers, infected USB sticks and ransomware.

> TGuard is still young. Keep Microsoft Defender turned on.

## Features

**Real-time protection.** A Windows service watches Downloads, Desktop, Documents and the temp
folder of every user on the PC, plus any USB drive while it is plugged in. New files are scanned
as soon as they finish writing. Files that are locked while being written are retried until they
can be read. Anything malicious goes to an encrypted quarantine.

**Execution blocking.** Every new process is checked: the executable, its command line
(Base64-encoded PowerShell is decoded first) and the script it was asked to run. A malicious
process is terminated and its file quarantined.

**Anti-ransomware.** Hidden decoy files are placed in Documents, Desktop, Pictures, Videos and
Music. If a program changes or renames a decoy, or renames lots of files to new extensions within seconds,
TGuard stops the process responsible and quarantines it. System files under `C:\Windows` are
never quarantined.

**Email protection.** IMAP accounts (Gmail and Yahoo with an app password, SAPO, iCloud, or any
other IMAP server) are checked every 3 minutes for malicious attachments, phishing links and
spoofed senders. Dangerous messages can be moved to a `TGuard Quarentena` folder. Passwords are
stored encrypted with Windows DPAPI. Microsoft no longer allows IMAP with a password on
Outlook.com and Hotmail, so for those accounts TGuard scans the attachments opened in desktop
Outlook instead.

**Web protection.** A browser extension for Chrome and Edge blocks phishing pages and fake
copies of Portuguese services (CGD, Millennium, MB WAY, CTT, Finanças, EDP and others). It uses
the same signed lists as the desktop app. Install it from Settings > Web protection, or unzip
`TGuard-Web` from Releases and load the folder as an unpacked extension.

**USB drives.** Removable drives are scanned when plugged in, including `autorun.inf` tricks.

**PC security check.** Defender, firewall, Windows Update, UAC, SMBv1, Remote Desktop, BitLocker,
Wi-Fi security and suspicious startup entries.

**Scanning engine.** Written from scratch, no third-party AV engine:

- SHA-256 signatures from MalwareBazaar plus the lists maintained on luis-tavares.pt
- YARA-style rules in plain JSON, see [`default.rules.json`](src/TGuard.Core/Resources/default.rules.json)
- file type detection by content, so a `.pdf` that is really an `.exe` gets caught
- a PE parser for Windows executables (packers, W+X sections, injection imports)
- Office macros, including decompressing the VBA source (MS-OVBA)
- PDF, RTF, HTML, JavaScript/VBScript, `.lnk` shortcuts, nested ZIPs and password-protected ZIPs
- Authenticode verification, so signed software from known vendors isn't flagged
- Mark-of-the-Web, so where a file came from is part of the verdict
- phishing link analysis for Portuguese banks and services, including look-alike domains and homoglyphs
- an allow list for confirmed false positives, and stronger evidence required for software
  installed in Program Files or Windows
- a weekly CI sweep of about 300,000 clean files to catch false positives before a release

Every file gets a score from 0 to 100. 40 and up is suspicious, 80 and up is malicious.

**Updates.** Signatures, URL lists and new versions of TGuard are checked every 3 hours.
Signatures are installed silently; new versions are installed once you confirm. Everything is
signed in GitHub Actions with ECDSA keys and verified on the PC, so the web server can't push
anything by itself. See [`server/`](server/README.md).

**Account (optional).** A PC can be linked to a [luis-tavares.pt](https://luis-tavares.pt)
account. The client area then shows the protection status of each PC, the threats it found, the
quarantine, the protected email accounts and the Windows security check, and, if you allow it on
the PC, can ask it to scan, update or change a protection. From the app you can also report a scam or a false
positive, open a support ticket, or use the live chat in Help, which can also ask for remote
assistance through Windows Quick Assist.

## Installing

Download `TGuard-Setup-x.y.z.exe` from [Releases](https://github.com/Tavaress21/tguard/releases)
or from [luis-tavares.pt/projetos/tguard](https://luis-tavares.pt/projetos/tguard) and run it.
Setup installs the .NET 8 Desktop Runtime if it is missing. The installer isn't code-signed yet,
so SmartScreen asks for confirmation ("More info", then "Run anyway").

## Privacy

Files and emails are always scanned on the PC. They are never uploaded.

| What | When | Sent |
| --- | --- | --- |
| Usage statistics | only if you agree when TGuard first starts, then once a day | random install ID, TGuard and Windows version, number of signatures, which protections are on, quarantine and threat counts, date of the last scan and update |
| Threat sharing | asked together with the statistics | detection name, where it was found (file, email, web...), score and date of each threat |
| Linked account | only after you link the PC | the above every 5 minutes, plus the file name (or the email subject and sender) and the action taken, the files in quarantine, the protected email addresses and the Windows security check |

Each of these can be turned off in Settings. Unlinking the PC, from the app or from the client
area, stops the account data straight away.

**Remote actions.** A linked PC only accepts requests from the client area (scan, update, check
email, turn a protection on or off, restore or delete a quarantined file) after you turn on
"Allow actions from the client area" in Settings > Account. Only the account the PC is linked to
can send them, and each one shows up on the PC as a notification.

**New versions.** Signatures update silently every 3 hours. When a new version of TGuard is
ready, the app asks "Update now" or "Remind me later" the next time you open it, unless you turn
on "Install new versions without asking".

## Building

You need the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
dotnet build TGuard.sln -c Release
dotnet run --project tests/TGuard.Tests -c Release
node tests/browser/extension.test.mjs
dotnet run --project src/TGuard.Cli -- scan C:\Users\me\Downloads
dotnet run --project src/TGuard.Cli -- check
```

Every push is built and tested on Windows by GitHub Actions. The integration tests install the
service, drop harmless samples and check that they are caught, quarantined or killed, simulate
ransomware against the decoys, run an update end to end against a local server, and install and
uninstall the setup. The installer is built with [Inno Setup](https://jrsoftware.org/isinfo.php)
from `installer/TGuard.iss`.

## Layout

```
src/TGuard.Core      scanning engine, email client, update and site clients
src/TGuard.Service   Windows service: real-time, processes, USB, ransomware, email, updates
src/TGuard.App       desktop app (WPF), Portuguese and English
src/TGuard.Cli       command line, also used by CI to sign updates
browser/             web protection extension (Manifest V3)
installer/           Inno Setup script and release notes
server/              update mirror for cPanel
tests/               engine tests and extension tests
```

## Contributing

New detection rules are welcome. A rule is a few lines of JSON: open a pull request with a short
description and, if you can, the SHA-256 of a sample it catches. Scams and false positives can
also be reported at [luis-tavares.pt/tguard/denunciar](https://luis-tavares.pt/tguard/denunciar).

## License

[MIT](LICENSE) © Luís Tavares, [luis-tavares.pt](https://luis-tavares.pt)

Fonts: [Bagel Fat One](https://fonts.google.com/specimen/Bagel+Fat+One) and
[Outfit](https://fonts.google.com/specimen/Outfit), SIL Open Font License.
