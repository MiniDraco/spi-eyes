# SPI-Eyes capability probe -- self-elevating launcher.
# Right-click -> "Run with PowerShell", or:  powershell -ExecutionPolicy Bypass -File run-elevated.ps1
# Elevation is needed to read TPM / Secure Boot / dbx / db (otherwise those show NOT-ASSESSED).
# The probe is READ-ONLY: it loads no kernel driver and writes nothing to firmware.

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Requesting elevation (UAC)..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList `
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`""
    exit
}

Set-Location $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"
python -m capability_probe
Write-Host ""
Read-Host "Press Enter to close"
