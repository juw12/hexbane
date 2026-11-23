; Hexbane for Windows - per-user installer (no admin rights). build.py compiles it with:
;   iscc /DAppVersion=1.0.0 /DSourceDir=<dist\Hexbane> /DOutputDir=<dist> /DIconFile=<build\hexbane.ico> hexbane.iss
; Installs to %LOCALAPPDATA%\Programs\Hexbane, adds Hexbane to the Start menu (and optionally the desktop) and lists it
; in Settings > Apps. The window keeps its data (what you saved in it) in %LOCALAPPDATA%\Hexbane, which
; uninstalling leaves in place so a reinstall finds it again.

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "dist\Hexbane"
#endif
#ifndef OutputDir
  #define OutputDir "dist"
#endif
#ifndef IconFile
  #define IconFile "build\hexbane.ico"
#endif

[Setup]
AppId={{E81247BA-698B-569E-A6DE-E1E1C366EEFB}
AppName=Hexbane
AppVersion={#AppVersion}
AppVerName=Hexbane {#AppVersion}
AppPublisher=Juwen Lie
AppPublisherURL=https://juw12.github.io/hexbane/
AppSupportURL=https://github.com/juw12/hexbane
DefaultDirName={autopf}\Hexbane
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename=Hexbane-Windows-Setup
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\Hexbane.exe
UninstallDisplayName=Hexbane
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=no
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\Hexbane"; Filename: "{app}\Hexbane.exe"; Comment: "Check AI agent skills, MCP servers and tools before you load them"
Name: "{userdesktop}\Hexbane"; Filename: "{app}\Hexbane.exe"; Comment: "Check AI agent skills, MCP servers and tools before you load them"; Tasks: desktopicon

[Run]
Filename: "{app}\Hexbane.exe"; Description: "{cm:LaunchProgram,Hexbane}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\Hexbane.exe"; Parameters: "--stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopHexbane"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  { Updating: close an open Hexbane window first so its files can be replaced. }
  if FileExists(ExpandConstant('{app}\Hexbane.exe')) then
    Exec(ExpandConstant('{app}\Hexbane.exe'), '--stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
