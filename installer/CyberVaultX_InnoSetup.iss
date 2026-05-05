; CyberVault X Inno Setup template
; Build the EXE first with build_release.bat, then compile this script in Inno Setup.

#define MyAppName "CyberVault X"
#define MyAppVersion "5.7.2"
#define MyAppPublisher "CyberVault X Demo"
#define MyAppExeName "CyberVaultX.exe"

[Setup]
AppId={{D4EA62F4-6E7A-46C5-9E8C-0A56F0A56000}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\CyberVault X
DefaultGroupName=CyberVault X
DisableProgramGroupPage=yes
OutputDir=..\dist_installer
OutputBaseFilename=CyberVaultX_v5.7.2_Strict_Final_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\app_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "..\dist\CyberVaultX\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\CyberVault X"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\CyberVault X"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch CyberVault X"; Flags: nowait postinstall skipifsilent
