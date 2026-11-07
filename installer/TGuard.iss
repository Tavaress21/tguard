#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{CEFAB7AD-A3D3-426B-A093-8AB27FB4FB96}
AppName=TGuard
AppVersion={#AppVersion}
AppVerName=TGuard {#AppVersion}
AppPublisher=Luís Tavares
AppPublisherURL=https://luis-tavares.pt
AppSupportURL=https://github.com/Tavaress21/tguard
DefaultDirName={autopf}\TGuard
DefaultGroupName=TGuard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\publish
OutputBaseFilename=TGuard-Setup-{#AppVersion}
SetupIconFile=..\src\TGuard.App\Assets\tguard.ico
UninstallDisplayIcon={app}\app\TGuard.exe
UninstallDisplayName=TGuard
LicenseFile=..\LICENSE
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
CloseApplications=no
UsedUserAreasWarning=no

[Languages]
Name: "pt"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
pt.LaunchApp=Abrir o TGuard
en.LaunchApp=Open TGuard
pt.DesktopIcon=Criar um atalho no Ambiente de Trabalho
en.DesktopIcon=Create a desktop shortcut
pt.DotNetDownload=A descarregar o .NET 8 Desktop Runtime da Microsoft…
en.DotNetDownload=Downloading the .NET 8 Desktop Runtime from Microsoft...
pt.DotNetFailed=Não foi possível instalar o .NET 8 Desktop Runtime. Instala-o manualmente em https://dotnet.microsoft.com/download/dotnet/8.0 e volta a correr o instalador.
en.DotNetFailed=Could not install the .NET 8 Desktop Runtime. Install it from https://dotnet.microsoft.com/download/dotnet/8.0 and run setup again.
pt.InstallingService=A ativar a proteção…
en.InstallingService=Turning protection on...

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked

[Dirs]
Name: "{commonappdata}\TGuard"

[Files]
Source: "..\publish\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\cli\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\publish\browser\*"; DestDir: "{app}\browser"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\TGuard"; Filename: "{app}\app\TGuard.exe"
Name: "{autodesktop}\TGuard"; Filename: "{app}\app\TGuard.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "TGuard"; \
  ValueData: """{app}\app\TGuard.exe"" --tray"; Flags: uninsdeletevalue

[Run]
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\TGuard"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX"; Flags: runhidden waituntilterminated; StatusMsg: "{cm:InstallingService}"
Filename: "{sys}\sc.exe"; Parameters: "create TGuard binPath= ""{app}\service\TGuard.Service.exe"" start= auto DisplayName= ""TGuard Protection"""; Flags: runhidden waituntilterminated; StatusMsg: "{cm:InstallingService}"
Filename: "{sys}\sc.exe"; Parameters: "config TGuard binPath= ""{app}\service\TGuard.Service.exe"" start= auto"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "description TGuard ""Real-time protection, execution blocking and scans (luis-tavares.pt)"""; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure TGuard reset= 86400 actions= restart/5000/restart/5000/restart/30000"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start TGuard"; Flags: runhidden waituntilterminated
Filename: "{app}\app\TGuard.exe"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/f /im TGuard.exe"; Flags: runhidden waituntilterminated; RunOnceId: "KillApp"
Filename: "{sys}\sc.exe"; Parameters: "stop TGuard"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{sys}\timeout.exe"; Parameters: "/t 3 /nobreak"; Flags: runhidden waituntilterminated; RunOnceId: "WaitService"
Filename: "{sys}\sc.exe"; Parameters: "delete TGuard"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteService"

[Code]
var
  DownloadPage: TDownloadWizardPage;

function DotNetDesktop8Installed: Boolean;
var
  FindRec: TFindRec;
begin
  Result := FindFirst(ExpandConstant('{commonpf64}\dotnet\shared\Microsoft.WindowsDesktop.App\8.*'), FindRec);
  if Result then
    FindClose(FindRec);
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing), CustomMessage('DotNetDownload'), nil);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if (CurPageID = wpReady) and not DotNetDesktop8Installed then
  begin
    DownloadPage.Clear;
    DownloadPage.Add('https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe', 'windowsdesktop-runtime-8-x64.exe', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
      except
        MsgBox(CustomMessage('DotNetFailed'), mbCriticalError, MB_OK);
        Result := False;
        Exit;
      end;
    finally
      DownloadPage.Hide;
    end;
    if not Exec(ExpandConstant('{tmp}\windowsdesktop-runtime-8-x64.exe'), '/install /quiet /norestart', '', SW_SHOW, ewWaitUntilTerminated, ResultCode)
       or ((ResultCode <> 0) and (ResultCode <> 3010) and (ResultCode <> 1638)) then
    begin
      MsgBox(CustomMessage('DotNetFailed'), mbCriticalError, MB_OK);
      Result := False;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im TGuard.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if Exec(ExpandConstant('{sys}\sc.exe'), 'stop TGuard', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then
    Sleep(3000);
  Result := '';
end;
