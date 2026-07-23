# Build SPI-Eyes.exe -- a standalone Windows GUI executable (no Python needed to run).
#   pip install pyinstaller
#   .\build-exe.ps1
# Output: dist\SPI-Eyes.exe  (~14 MB, onefile, windowed)
#
# biosutilities (Dell PFS / AMI / Insyde unwrapping) is EXCLUDED to keep the exe lean;
# the GUI still runs everything else. Drop --exclude-module to bundle it.

python -m PyInstaller --onefile --windowed --name SPI-Eyes --noconfirm --clean `
    --add-data "corpus/references;corpus/references" `
    --hidden-import capability_probe.probes_windows `
    --hidden-import capability_probe.probes_linux `
    --hidden-import capability_probe.probes_macos `
    --hidden-import capability_probe.inventory `
    --hidden-import corpus.coproc `
    --hidden-import corpus.unwrap `
    --hidden-import corpus.client `
    --hidden-import corpus.lvfs `
    --hidden-import corpus.ingest `
    --exclude-module biosutilities `
    gui/spi_eyes_gui.py

if ($LASTEXITCODE -eq 0) { Write-Host "`nBuilt dist\SPI-Eyes.exe" -ForegroundColor Green }
