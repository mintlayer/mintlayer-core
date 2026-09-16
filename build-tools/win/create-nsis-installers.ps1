# Renders the NSIS installer scripts from the templates in .\nsi\ and builds
# them with makensis. Produces:
#  - Mintlayer_Node_win_<Version>_Setup.exe       (CLI daemons and tools)
#  - Mintlayer_Node_GUI_win_<Version>_Setup.exe   (GUI)
#
# Requires: NSIS 3 on PATH (or in the default install location); LICENSE.txt
# (as produced by create-license.ps1) and the release binaries under
# target\release must exist before this script runs.

param (
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"

$TemplateDir = Join-Path $PSScriptRoot "nsi"

# The version comes from the git tag and ends up inside NSIS string literals;
# restrict it to the same charset the Linux packages allow so it cannot break
# out of them.
if ($Version -notmatch '^[0-9][0-9A-Za-z.~+-]*$') {
    throw "invalid version '$Version' (expected digits-first X.Y.Z[-suffix])"
}

if (-not (Test-Path "LICENSE.txt")) {
    throw "LICENSE.txt not found; run create-license.ps1 first"
}

$makensis = Get-Command makensis.exe -ErrorAction SilentlyContinue
if ($null -ne $makensis) {
    $makensisPath = $makensis.Source
} else {
    $makensisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
}
if (-not (Test-Path $makensisPath)) {
    throw "makensis.exe not found on PATH or in the default NSIS location"
}
Write-Host "Using makensis at: $makensisPath"

# The installer templates pack the binaries straight from target\release
# (the cargo release output this script expects to run against).
$requiredBinaries = @(
    "node-daemon.exe", "wallet-rpc-daemon.exe", "api-web-server.exe",
    "api-blockchain-scanner-daemon.exe", "dns-server.exe", "wallet-cli.exe",
    "wallet-address-generator.exe", "node-gui.exe"
)
foreach ($exe in $requiredBinaries) {
    $path = Join-Path "target\release" $exe
    if (-not (Test-Path $path)) {
        throw "required binary not found: $path"
    }
}

function Build-Installer {
    param (
        [string]$TemplateName,
        [string]$ScriptName
    )

    $template = Join-Path $TemplateDir $TemplateName
    $script = Join-Path $PWD $ScriptName

    Write-Host "Rendering $script from $template (version $Version)"
    $content = Get-Content -Raw -Path $template
    $content = $content.Replace("@VERSION@", $Version)
    # The templates pull in common.nsh from the template dir via
    # !addincludedir, so the !include resolves regardless of where makensis
    # runs.
    $content = $content.Replace("@NSI_DIR@", $TemplateDir)
    # Write ASCII without a BOM: the scripts are plain ASCII (keep the
    # templates ASCII-only) and makensis is picky about BOMs.
    [System.IO.File]::WriteAllText($script, $content, [System.Text.Encoding]::ASCII)

    Write-Host "Building $ScriptName"
    & $makensisPath $script
    # makensis exits 1 for warnings and 2 for errors; warnings are visible in
    # the output but allowed (consistent with the lintian/rpmlint gates).
    if ($LASTEXITCODE -ge 2) {
        throw "makensis failed for $ScriptName (exit $LASTEXITCODE)"
    }
}

Build-Installer -TemplateName "node.nsi.in" -ScriptName "installer-node.nsi"
Build-Installer -TemplateName "gui.nsi.in" -ScriptName "installer-gui.nsi"

$nodeOut = "Mintlayer_Node_win_${Version}_Setup.exe"
$guiOut = "Mintlayer_Node_GUI_win_${Version}_Setup.exe"
foreach ($out in @($nodeOut, $guiOut)) {
    if (-not (Test-Path $out)) {
        throw "installer was not produced: $out"
    }
    Write-Host "built $((Get-Item $out).Length) byte installer: $out"
}
