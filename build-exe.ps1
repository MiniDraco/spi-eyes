# Build SPI-Eyes.exe -- a standalone Windows GUI executable (no Python needed to run).
#   pip install pyinstaller
#   .\build-exe.ps1
# Output: dist\SPI-Eyes.exe  (~14 MB, onefile, windowed)
#
# To lock the exe to YOUR corpus server: create spi-eyes.ini (see spi-eyes.ini.example)
# before building -- it gets bundled in. Or just ship spi-eyes.ini next to the exe.
# biosutilities (Dell PFS / AMI / Insyde unwrapping) is EXCLUDED to keep the exe lean.

$data = @("--add-data", "corpus/references;corpus/references")
if (Test-Path "spi-eyes.ini") {
    $data += @("--add-data", "spi-eyes.ini;.")
    Write-Host "bundling spi-eyes.ini (server locked to its [server] url)" -ForegroundColor Cyan
}

$hidden = @(
    "capability_probe.probes_windows", "capability_probe.probes_linux",
    "capability_probe.probes_macos", "capability_probe.inventory",
    "corpus.coproc", "corpus.unwrap", "corpus.client", "corpus.config",
    "corpus.lvfs", "corpus.ingest"
) | ForEach-Object { @("--hidden-import", $_) }

python -m PyInstaller --onefile --windowed --name SPI-Eyes --noconfirm --clean `
    @data @hidden --exclude-module biosutilities gui/spi_eyes_gui.py

if ($LASTEXITCODE -eq 0) { Write-Host "`nBuilt dist\SPI-Eyes.exe" -ForegroundColor Green }
