; ===========================================================================
; SQ 授权系统 · NSIS 安装脚本（NSIS 3.x，Unicode）
;
; 编译（Windows，已安装 NSIS——winget install NSIS.NSIS 或官网下载）：
;   makensis /DAPP_DIR=<installer_out\app 目录> installer\sq_license_setup.nsi
; 产物：SQ授权系统-Setup-1.0.0.exe（单文件向导式安装器）
;
; 素材目录由 installer/make_package.py 生成（含四个程序 + 发布清单）。
; ===========================================================================

Unicode true
!include "MUI2.nsh"

!ifndef APP_DIR
  !define APP_DIR "..\installer_out\app"
!endif

!define APP_NAME "SQ 授权系统"
!define APP_VERSION "1.0.0"
!define APP_PUBLISHER "苏丠"

Name "${APP_NAME}"
OutFile "SQ授权系统-Setup-${APP_VERSION}.exe"
InstallDir "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "Software\${APP_NAME}" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; ---------------------------------------------------------------------------
; 界面（简体中文向导）
; ---------------------------------------------------------------------------
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

; ---------------------------------------------------------------------------
; 组件
; ---------------------------------------------------------------------------
Section "核心程序（必需）" SEC_CORE
  SectionIn RO
  SetOutPath "$INSTDIR"
  File /r "${APP_DIR}\*.*"
  WriteRegStr HKLM "Software\${APP_NAME}" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\卸载程序.exe"
SectionEnd

Section "开始菜单快捷方式" SEC_STARTMENU
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\本地服务器.lnk" "$INSTDIR\本地服务器.exe"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\管理端.lnk" "$INSTDIR\管理端.exe"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\验证端.lnk" "$INSTDIR\验证端.exe"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\主控端.lnk" "$INSTDIR\主控端.exe"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\卸载.lnk" "$INSTDIR\卸载程序.exe"
SectionEnd

Section "桌面快捷方式（验证端）" SEC_DESKTOP
  CreateShortCut "$DESKTOP\SQ 验证端.lnk" "$INSTDIR\验证端.exe"
SectionEnd

; ---------------------------------------------------------------------------
; 卸载
; 说明：data/ 与 server_config.json 是运行时数据（含授权库与密钥），
; 卸载**不自动删除**——防止误删造成授权数据丢失；如需清空请手动处理。
; ---------------------------------------------------------------------------
Section "Uninstall"
  Delete "$SMPROGRAMS\${APP_NAME}\*.lnk"
  RMDir "$SMPROGRAMS\${APP_NAME}"
  Delete "$DESKTOP\SQ 验证端.lnk"
  Delete "$INSTDIR\本地服务器.exe"
  Delete "$INSTDIR\管理端.exe"
  Delete "$INSTDIR\验证端.exe"
  Delete "$INSTDIR\主控端.exe"
  Delete "$INSTDIR\release_manifest.json"
  Delete "$INSTDIR\release_manifest.sig"
  RMDir /r "$INSTDIR\releases"
  RMDir /r "$INSTDIR\assets"
  Delete "$INSTDIR\安装说明.txt"
  Delete "$INSTDIR\卸载程序.exe"
  ; 数据目录与配置保留（见上）；空目录尝试移除
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\${APP_NAME}"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_CORE} "四个程序与发布清单（必需）"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_STARTMENU} "在开始菜单创建快捷方式"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} "在桌面创建验证端快捷方式"
!insertmacro MUI_FUNCTION_DESCRIPTION_END
