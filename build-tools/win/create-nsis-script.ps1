# build-tools/win/create-nsis-script.ps1

param (
    [Parameter(Mandatory=$true)]
    [string]$Version
)

Write-Host "Debug: Received Version = $Version"

$outFileName = "Mintlayer_Node_GUI_win_${Version}_Setup.exe"

$NSIS_SCRIPT = @"
; Mintlayer Node GUI Installer Script
!define APPNAME "Mintlayer Node GUI"
!define COMPANYNAME "Mintlayer"
!define DESCRIPTION "Mintlayer Node GUI Application"
!define VERSION "${Version}"

; Main Install settings
Name "`${APPNAME}"
InstallDir "`$PROGRAMFILES64\`${COMPANYNAME}\`${APPNAME}"
OutFile "$outFileName"

; Modern interface settings
!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ABORTWARNING

; License page
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

Section "Install"
    ; Debug output
    DetailPrint "Debug: INSTDIR before check is '`$`INSTDIR'"

    ; Check if INSTDIR is empty and set a fallback if it is
    `${If} "`$`INSTDIR" == ""
        StrCpy `$`INSTDIR "`$`${PROGRAMFILES64}\`${COMPANYNAME}\`${APPNAME}"
        DetailPrint "Debug: INSTDIR was empty, set to fallback: '`$`INSTDIR'"
    `${EndIf}

    ; Set output path to the installation directory
    SetOutPath "`$`INSTDIR"

    ; Add files
    File "target\release\node-gui.exe"
    File "LICENSE.txt"

    ; Create desktop shortcut
    CreateShortcut "`$`DESKTOP\`${APPNAME}.lnk" "`$`INSTDIR\node-gui.exe"

    ; Create Start Menu shortcut
    CreateDirectory "`${SMPROGRAMS}\`${COMPANYNAME}"
    CreateShortcut "`${SMPROGRAMS}\`${COMPANYNAME}\`${APPNAME}.lnk" "`${INSTDIR}\node-gui.exe"

    ; Write the uninstall keys for Windows
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}" "DisplayName" "`${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}" "UninstallString" '"`$`INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}" "DisplayVersion" "`${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}" "Publisher" "`${COMPANYNAME}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}" "NoRepair" 1

    ; Create uninstaller
    WriteUninstaller "`$`INSTDIR\uninstall.exe"

SectionEnd

Section "Uninstall"
    ; Remove files
    Delete "`$`INSTDIR\node-gui.exe"
    Delete "`$`INSTDIR\LICENSE.txt"
    Delete "`$`INSTDIR\uninstall.exe"

    ; Remove shortcuts
    Delete "`${DESKTOP}\`${APPNAME}.lnk"
    Delete "`${SMPROGRAMS}\`${COMPANYNAME}\`${APPNAME}.lnk"
    RMDir  "`${SMPROGRAMS}\`${COMPANYNAME}" 

    ; Remove directories used
    RMDir "`$`INSTDIR"

    ; Remove uninstall registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\`${COMPANYNAME} `${APPNAME}"
SectionEnd
"@

# Remove any potential UTF-8 BOM and ensure ASCII encoding
$NSIS_SCRIPT = $NSIS_SCRIPT.TrimStart([char]0xFEFF)
[System.IO.File]::WriteAllLines("installer.nsi", $NSIS_SCRIPT)