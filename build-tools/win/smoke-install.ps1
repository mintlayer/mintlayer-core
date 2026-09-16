# Install-and-uninstall smoke test for the NSIS installers produced by
# create-nsis-installers.ps1. Runs on a Windows machine (CI runners are
# administrator, so the machine-wide install works without prompts).
#
# For each installer: silent install, verify files, registry uninstall entry
# and (for the node installer) the machine PATH entry, run every installed
# binary with --help, then silently uninstall and verify everything is gone.
# The optional Windows service section is off by default and is not exercised
# here; verify it manually on a real system (see packaging instructions).

param (
    [Parameter(Mandatory = $true)]
    [string]$Installer,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Mintlayer Node", "Mintlayer Node GUI")]
    [string]$AppName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("node", "gui")]
    [string]$Kind,

    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:ProgramFiles (Join-Path "Mintlayer" $AppName)
$UninstKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mintlayer $AppName"

$Binaries = if ($Kind -eq "node") {
    @(
        "node-daemon", "wallet-rpc-daemon", "api-web-server",
        "api-blockchain-scanner-daemon", "dns-server", "wallet-cli",
        "wallet-address-generator"
    )
} else {
    @("node-gui")
}

function Assert-PathEntry {
    param ([bool]$ShouldExist)
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $present = ($machinePath -split ";" -contains $InstallDir)
    if ($ShouldExist -and -not $present) {
        throw "machine PATH does not contain '$InstallDir'"
    }
    if (-not $ShouldExist -and $present) {
        throw "machine PATH still contains '$InstallDir'"
    }
}

Write-Host "== silent install: $Installer"
$p = Start-Process -FilePath $Installer -ArgumentList "/S" -Wait -PassThru
if ($p.ExitCode -ne 0) {
    throw "installer exited with $($p.ExitCode)"
}

Write-Host "== files and uninstall registry entry"
foreach ($bin in $Binaries) {
    $exe = Join-Path $InstallDir "$bin.exe"
    if (-not (Test-Path $exe)) {
        throw "not installed: $exe"
    }
}
if (-not (Test-Path (Join-Path $InstallDir "LICENSE.txt"))) {
    throw "not installed: LICENSE.txt"
}
if (-not (Test-Path (Join-Path $InstallDir "uninstall.exe"))) {
    throw "not installed: uninstall.exe"
}

$reg = Get-ItemProperty -Path $UninstKey -ErrorAction SilentlyContinue
if ($null -eq $reg) {
    throw "uninstall registry key missing: $UninstKey"
}
if ($reg.DisplayVersion -ne $Version) {
    throw "DisplayVersion is '$($reg.DisplayVersion)', expected '$Version'"
}
Write-Host "  ok: files + registry (DisplayVersion $Version)"

if ($Kind -eq "node") {
    Write-Host "== machine PATH"
    Assert-PathEntry -ShouldExist $true
    Write-Host "  ok: PATH contains $InstallDir"
}

Write-Host "== binaries answer --help"
foreach ($bin in $Binaries) {
    $exe = Join-Path $InstallDir "$bin.exe"
    & $exe --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "$bin --help exited with $LASTEXITCODE"
    }
    Write-Host "  ok: $bin --help"
}

Write-Host "== silent uninstall"
$uninstaller = Join-Path $InstallDir "uninstall.exe"
# '_?=' pins the uninstaller to the install dir (unquoted, as documented) so
# it does not copy itself to a temp location, which would make -Wait return
# before deletion finishes.
$p = Start-Process -FilePath $uninstaller -ArgumentList "/S", "_?=$InstallDir" -Wait -PassThru
if ($p.ExitCode -ne 0) {
    throw "uninstaller exited with $($p.ExitCode)"
}
# The uninstaller may lag a little even with '_?='; poll briefly.
$deadline = (Get-Date).AddSeconds(30)
while ((Test-Path (Join-Path $InstallDir "uninstall.exe")) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}

foreach ($bin in $Binaries) {
    if (Test-Path (Join-Path $InstallDir "$bin.exe")) {
        throw "uninstall left binaries behind in $InstallDir"
    }
}
if (Get-ItemProperty -Path $UninstKey -ErrorAction SilentlyContinue) {
    throw "uninstall registry key still present: $UninstKey"
}
if ($Kind -eq "node") {
    Assert-PathEntry -ShouldExist $false
    Write-Host "  ok: binaries, registry and PATH cleaned up"
} else {
    Write-Host "  ok: binaries and registry cleaned up"
}

Write-Host "smoke test passed for $AppName"
