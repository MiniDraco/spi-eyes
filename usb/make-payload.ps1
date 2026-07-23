# Stage a USB payload: the minimal SPI-Eyes files needed to run the live-USB check.
# Copy the resulting usb-payload\ folder onto a USB stick; boot a Linux live-USB and run
#   sudo ./usb/spi-eyes-live.sh   from inside it.
#   .\usb\make-payload.ps1

$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "usb-payload"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $out | Out-Null

foreach ($item in @("corpus", "capability_probe", "usb")) {
    Copy-Item (Join-Path $root $item) (Join-Path $out $item) -Recurse
}
if (Test-Path (Join-Path $root "spi-eyes.ini")) {
    Copy-Item (Join-Path $root "spi-eyes.ini") $out
}
# drop caches / local state
Get-ChildItem $out -Recurse -Directory -Include "__pycache__", "out", "references" |
    Where-Object { $_.Name -eq "__pycache__" -or $_.Name -eq "out" } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Staged USB payload -> $out" -ForegroundColor Green
Write-Host "Copy that folder to a USB stick. Boot a Linux live-USB (Try mode) and run:"
Write-Host "  sudo ./usb/spi-eyes-live.sh"
