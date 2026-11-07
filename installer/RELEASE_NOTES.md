What's new in 0.5.1

- Far fewer false positives. A sweep of almost 300,000 clean files (Windows, Program Files and
  popular installers such as Chrome, Firefox, Zoom, Steam, Autenticação.gov and Visual Studio)
  now runs every week in CI. This release fixes everything it found:
  - text files such as C/C++ headers, libraries, logs and documentation are no longer treated
    as scripts;
  - software installed in Program Files or Windows needs much stronger evidence before it is
    flagged;
  - names like "Ionic.Zip.dll" or "Template.doc.vb" are no longer reported as fake double
    extensions;
  - Start menu shortcuts that open a developer command prompt are no longer flagged.

What's new in 0.5.0

- Live chat inside TGuard: open Help to talk to luis-tavares.pt without leaving the app. If the
  PC is linked to your account, your name and email are filled in for you, and replies show up as
  a notification even when TGuard is in the tray.
- "Ask for remote assistance": tells the technician you need help on your screen. They send you a
  code in the chat and you connect with Windows Quick Assist, so nothing happens without your
  permission and you can end the session at any time.

What's new in 0.4.0

- New versions are no longer installed behind your back: when one is ready, TGuard asks
  "Update now" or "Remind me later" the next time you open it. Turn on "Install new versions
  without asking" in Settings if you prefer the old behaviour.
- On first start TGuard asks whether you want to share anonymous statistics. Nothing is shared
  until you say yes, and you can change it at any time in Settings.
- Remote actions from the luis-tavares.pt client area are now off until you allow them in
  Settings > Account. Once allowed, you can scan, update, check email, turn protections on or off
  and restore or delete quarantined files from the site. Every request shows up as a notification
  on the PC.
- The client area now shows the files in quarantine, the protected email accounts, the PC
  security check and the scan that is running.
- Fixes: a module that hits an unexpected error restarts on its own instead of stopping the
  service, and MalwareBazaar signatures are published again.

Windows SmartScreen may warn that the publisher is unknown because the installer isn't
code-signed yet. Click "More info" and then "Run anyway".

Keep Microsoft Defender turned on: TGuard is meant to run alongside it.
