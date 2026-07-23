# USB boot tool — read firmware from a clean environment

Boot a Linux live-USB, and SPI-Eyes reads the SPI flash **from a known-clean OS** and
line-checks it against the corpus — without touching the machine's disk, installing
anything, or clipping a chip. This is the safest way to check firmware with no hardware.

## Why boot from USB (not just run on the host OS)?
Running a read on the host's own OS trusts an OS that might already be compromised. A
live-USB boots a fresh OS **entirely from RAM** — the host's installed OS never runs, so
it can't tamper with or lie about the read. Shut down, pull the USB, and the machine is
**byte-for-byte unchanged**. Read-only throughout — it never writes firmware, so it can't
brick anything.

## Honest ceiling (read this)
It's still a **software** read (through the chipset's SPI controller), which a ring -2/-3
implant (SMM / Intel ME / AMD PSP) can still intercept. So the best verdict is
**CANNOT-VERIFY** (on a match) or **ANOMALOUS** (on a deviation) — it removes the *OS-level*
lie, not the *firmware-level* one. It **catches the commodity implant tier** with zero
hardware. For an earned CLEAN you still need an external clip read or a DRTM quote.

## Use it
1. Make a Linux live-USB (Ubuntu is easiest — write the ISO with Rufus/BalenaEtcher). Boot
   it in **"Try Ubuntu"** mode (do NOT install).
2. Put this SPI-Eyes folder on a second USB stick (or `git clone` it once booted).
   From Windows you can stage it: `.\usb\make-payload.ps1` → copies the needed files into
   `usb-payload\`, which you drop on the stick.
3. In the live session, open a terminal and run:
   ```bash
   cd /path/to/spi-eyes
   sudo ./usb/spi-eyes-live.sh
   ```
4. It auto-detects your vendor/model/BIOS-version (`dmidecode`), reads the flash twice
   (confirms stability), and prints the line-by-line verdict vs the corpus.

If the exact BIOS version isn't in the corpus, you'll get **CANNOT-VERIFY** with a note to
submit that version's manifest (`python -m corpus submit`) — never a wrong-version match.
