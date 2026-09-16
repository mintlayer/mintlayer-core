; Shared NSIS macros for the Mintlayer installers.
; The rendered scripts include this file; create-nsis-installers.ps1 passes
; the template directory to makensis via /I so the bare name resolves.
; Pure ASCII only (the generator writes the rendered script as ASCII).

; Silently remove a previously installed version of the product whose
; uninstall registry entries live under ${UNINSTKEY}. The stored
; UninstallString includes quotes, which must not be re-quoted, so they are
; stripped and the command line is rebuilt here; per the NSIS documentation
; the _?= parameter must come last and unquoted.
!macro MintlayerRemovePreviousInstall
    ReadRegStr $R0 HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "UninstallString"
    ReadRegStr $R1 HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "InstallLocation"
    ${If} $R0 != ""
        DetailPrint "Removing previous installation..."
        StrCpy $R2 $R0 1
        ${If} $R2 == "$\""
            StrLen $R3 $R0
            IntOp $R3 $R3 - 2
            StrCpy $R0 $R0 $R3 1
        ${EndIf}
        ${If} $R1 != ""
            ExecWait '"$R0" /S _?=$R1'
        ${Else}
            ExecWait '"$R0" /S _?=$INSTDIR'
        ${EndIf}
    ${EndIf}
!macroend

; Writes the standard uninstall registry entries for ${UNINSTKEY}.
!macro MintlayerUninstallRegistry
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "DisplayName" "${APPNAME}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "Publisher" "${COMPANYNAME}"
    WriteRegDWORD HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "NoModify" 1
    WriteRegDWORD HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\${UNINSTKEY}" \
        "NoRepair" 1
!macroend
