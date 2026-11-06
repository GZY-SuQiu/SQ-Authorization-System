; ===========================================================================
; SQ 授权系统 · Inno Setup 6 脚本（与 NSIS 版二选一）
;
; 编译：
;   A) GUI：用 Inno Setup 打开本文件 → Build
;   B) 命令行：ISCC.exe /DAPP_DIR=<installer_out\app 目录> installer\sq_license_setup.iss
; 产物：SQ授权系统-Setup-1.0.0.exe
;
; 中文界面：Inno 默认不含简中翻译文件；如需中文向导，把 ChineseSimplified.isl
; 放入 Inno 的 Languages 目录（社区翻译），然后取消下面 Languages 段的注释。
; ===========================================================================

#ifndef APP_DIR
  #define APP_DIR "..\installer_out\app"
#endif
#define APP_NAME "SQ 授权系统"
#define APP_VERSION "1.0.0"
#define APP_PUBLISHER "苏丠"

[Setup]
AppId={{8E1B2F14-9A5C-4D3E-B0A1-7C4D5E6F2A3B}
AppName={#APP_NAME}
AppVersion={#APP_VERSION}
AppPublisher={#APP_PUBLISHER}
DefaultDirName={autopf}\{#APP_NAME}
DefaultGroupName={#APP_NAME}
OutputBaseFilename=SQ授权系统-Setup-{#APP_VERSION}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayName={#APP_NAME}
WizardStyle=modern

; [Languages]
; Name: "chinese"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "startmenu"; Description: "创建开始菜单快捷方式"; GroupDescription: "附加任务:"
Name: "desktop"; Description: "创建桌面快捷方式（验证端）"; GroupDescription: "附加任务:"

[Files]
Source: "{#APP_DIR}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\本地服务器"; Filename: "{app}\本地服务器.exe"; Tasks: startmenu
Name: "{group}\管理端"; Filename: "{app}\管理端.exe"; Tasks: startmenu
Name: "{group}\验证端"; Filename: "{app}\验证端.exe"; Tasks: startmenu
Name: "{group}\主控端"; Filename: "{app}\主控端.exe"; Tasks: startmenu
Name: "{group}\卸载 {#APP_NAME}"; Filename: "{uninstallexe}"; Tasks: startmenu
Name: "{autodesktop}\SQ 验证端"; Filename: "{app}\验证端.exe"; Tasks: desktop

[Run]
Filename: "{app}\本地服务器.exe"; Description: "立即启动本地服务器"; Flags: postinstall nowait skipifsilent

; 卸载说明：data/ 与 server_config.json 为运行时生成文件（授权库与密钥），
; Inno 不跟踪此类文件——卸载时自动保留（保护数据）。
