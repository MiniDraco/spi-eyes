# External SPI read helper -- reads the flash N times via flashrom and confirms the
# reads are stable (identical hashes) before trusting the dump. An unstable read means
# bus contention or a bad clip, NOT evidence -- fix the physical setup and retry.
#
#   .\Read-ExternalSPI.ps1 -Programmer ft2232_spi:type=232H -Out spi-dump.bin
#   .\Read-ExternalSPI.ps1 -Programmer serprog:dev=COM4:115200 -Out spi-dump.bin   # Pi Pico
#
# SAFETY: power the target OFF and unplug it first. See read/README.md.

param(
    [string]$Programmer = "ft2232_spi:type=232H",
    [string]$Out = "spi-dump.bin",
    [int]$Reads = 3
)

if (-not (Get-Command flashrom -ErrorAction SilentlyContinue)) {
    Write-Host "flashrom not found in PATH. Install flashrom (flashrom.org) first." -ForegroundColor Red
    exit 1
}

Write-Host "Confirm the TARGET MACHINE IS POWERED OFF and the clip is seated." -ForegroundColor Yellow
Read-Host "Press Enter to read $Reads times via $Programmer"

$hashes = @()
$files = @()
for ($i = 1; $i -le $Reads; $i++) {
    $f = "spi-read-$i.bin"
    Write-Host "read $i/$Reads ..." -ForegroundColor Cyan
    & flashrom -p $Programmer -r $f
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $f)) {
        Write-Host "read $i failed (exit $LASTEXITCODE). Check clip seating / voltage / power-off." -ForegroundColor Red
        exit 1
    }
    $h = (Get-FileHash $f -Algorithm SHA256).Hash
    Write-Host "  sha256 = $h"
    $hashes += $h; $files += $f
}

if (($hashes | Select-Object -Unique).Count -eq 1) {
    Copy-Item $files[0] $Out -Force
    $files | ForEach-Object { Remove-Item $_ -ErrorAction SilentlyContinue }
    Write-Host "`nSTABLE read -> $Out (sha256 $($hashes[0]))" -ForegroundColor Green
    Write-Host "Next: python -m corpus check $Out --vendor <V> --model <M> --version <X> --read external"
} else {
    Write-Host "`nUNSTABLE reads (hashes differ) -- bus contention or bad clip, NOT evidence." -ForegroundColor Red
    Write-Host "Power the target fully off, reseat a GENUINE clip, and retry. Reads kept for inspection."
    exit 2
}
