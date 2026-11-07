param([string]$Target)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force $Target | Out-Null

$files = @{
    '7zip.exe'           = 'https://www.7-zip.org/a/7z2409-x64.exe'
    'vlc.exe'            = 'https://get.videolan.org/vlc/last/win64/'
    'notepadpp.exe'      = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe'
    'firefox.exe'        = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=pt-PT'
    'chrome.exe'         = 'https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe'
    'vscode.exe'         = 'https://update.code.visualstudio.com/latest/win32-x64-user/stable'
    'git.exe'            = 'https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.2/Git-2.47.0.2-64-bit.exe'
    'python.exe'         = 'https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe'
    'node.msi'           = 'https://nodejs.org/dist/v22.11.0/node-v22.11.0-x64.msi'
    'putty.msi'          = 'https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.81-installer.msi'
    'zoom.exe'           = 'https://zoom.us/client/latest/ZoomInstallerFull.exe?archType=x64'
    'discord.exe'        = 'https://discord.com/api/downloads/distributions/app/installers/latest?channel=stable&platform=win&arch=x64'
    'steam.exe'          = 'https://cdn.akamai.steamstatic.com/client/installer/SteamSetup.exe'
    'anydesk.exe'        = 'https://download.anydesk.com/AnyDesk.exe'
    'teamviewer.exe'     = 'https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe'
    'rustdesk.exe'       = 'https://github.com/rustdesk/rustdesk/releases/download/1.3.2/rustdesk-1.3.2-x86_64.exe'
    'obs.exe'            = 'https://cdn-fastly.obsproject.com/downloads/OBS-Studio-30.2.3-Windows-Installer.exe'
    'libreoffice.msi'    = 'https://download.documentfoundation.org/libreoffice/stable/24.8.2/win/x86_64/LibreOffice_24.8.2_Win_x86-64.msi'
    'autenticacao.msi'   = 'https://aplicacoes.autenticacao.gov.pt/apps/Autenticacao.gov_Win_x64_signed.msi'
    'sample.pdf'         = 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf'
    'rust-init.exe'      = 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
    'autoruns.zip'       = 'https://download.sysinternals.com/files/Autoruns.zip'
    'procexp.zip'        = 'https://download.sysinternals.com/files/ProcessExplorer.zip'
    'nirlauncher.zip'    = 'https://www.nirsoft.net/utils/winprefetchview-x64.zip'
}

foreach ($name in $files.Keys) {
    $out = Join-Path $Target $name
    try {
        Invoke-WebRequest -Uri $files[$name] -OutFile $out -UseBasicParsing -TimeoutSec 300 -MaximumRedirection 10
        "{0,-20} {1,12:N0} bytes" -f $name, (Get-Item $out).Length
    }
    catch {
        "{0,-20} download failed: {1}" -f $name, $_.Exception.Message
    }
}

Get-ChildItem $Target -Filter *.zip | ForEach-Object {
    Expand-Archive $_.FullName -DestinationPath (Join-Path $Target $_.BaseName) -Force -ErrorAction SilentlyContinue
}
