#!/usr/bin/env bash
# SPI-Eyes live-USB firmware check.
#
# Boot ANY Linux live-USB (Ubuntu/Fedora/etc.) in "Try" mode -- it runs from RAM and
# touches NOTHING on the machine's disk. Then, with this SPI-Eyes folder on a second
# USB (or cloned):
#     sudo ./usb/spi-eyes-live.sh
#
# It reads the SPI flash via the chipset (flashrom internal) FROM A CLEAN OS -- so the
# host's (possibly compromised) OS can't lie about the read -- and line-checks it
# against the corpus. READ-ONLY; it never writes firmware, so it cannot brick anything.
#
# Honest ceiling: this is still a *software* read (the chipset SPI controller), which a
# ring -2/-3 (SMM/ME) implant can still intercept -> verdict caps at CANNOT-VERIFY. It
# removes the OS-level lie, not the firmware-level one. For an earned CLEAN you still
# need an external clip read or a DRTM quote. But it catches the commodity implant tier
# with no hardware, no clip, and no change to the machine.
set -uo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "run as root:  sudo $0"; exit 1
fi

DIR="$(cd "$(dirname "$0")/.." && pwd)"     # repo root (this script lives in usb/)

# ensure deps (best-effort across distros)
if ! command -v flashrom >/dev/null 2>&1; then
    echo "[*] installing flashrom + python3 ..."
    { apt-get update -y && apt-get install -y flashrom python3; } 2>/dev/null \
        || dnf install -y flashrom python3 2>/dev/null \
        || pacman -Sy --noconfirm flashrom python 2>/dev/null \
        || { echo "could not auto-install flashrom -- install it and re-run."; exit 1; }
fi

# identify the machine (for the version-exact corpus lookup)
V=$(dmidecode -s system-manufacturer 2>/dev/null | head -1)
M=$(dmidecode -s system-product-name 2>/dev/null | head -1)
[ -z "${M:-}" ] && M=$(dmidecode -s baseboard-product-name 2>/dev/null | head -1)
VER=$(dmidecode -s bios-version 2>/dev/null | head -1)
echo "[*] machine: ${V:-?} / ${M:-?} / BIOS ${VER:-?}"

# read twice, off the chipset, and confirm stability (unstable = contention, not evidence)
echo "[*] reading SPI flash (internal, read-only) -- takes a minute ..."
flashrom -p internal -r /tmp/spi1.bin || { echo "flashrom read failed (region may be locked). Verdict: CANNOT-VERIFY."; exit 2; }
flashrom -p internal -r /tmp/spi2.bin || { echo "second read failed. Verdict: CANNOT-VERIFY."; exit 2; }
if ! cmp -s /tmp/spi1.bin /tmp/spi2.bin; then
    echo "[!] UNSTABLE read (the two reads differ) -- not evidence. Verdict: CANNOT-VERIFY."; exit 2
fi

echo "[*] stable read. line-checking against the corpus ..."
cd "$DIR"
python3 -m corpus check /tmp/spi1.bin --vendor "${V:-}" --model "${M:-}" --version "${VER:-}" --read software
