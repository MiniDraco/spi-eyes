# External SPI read — the trustworthy read path (closes the loop)

A software/internal read of the SPI flash can be lied to by a resident ring -2/-3
implant, so it is capped at **CANNOT-VERIFY**. An **external read** — clipping the flash
chip and reading it with an independent programmer, off the CPU — is the read a resident
implant cannot spoof. It is the only path to an **earned CLEAN** for flash contents
(WHITEPAPER §5). This is the one hardware step in SPI-Eyes.

## What you need (pick one)
| Tier | Kit | ~Cost | Notes |
|---|---|---|---|
| **Ultra-budget** | **CH341A** (black board) + SOIC-8 clip + flashrom | ~$5 | works, but has 2 gotchas — see below. `-p ch341a_spi` |
| **Recommended** | **Tigard** (FT2232H) + SOIC-8 clip + flashrom | ~$39 | proper level-shifting — kills the #1 failure (5V on a 3.3V part) |
| Cheapest DIY | **Pi Pico + pico-serprog** + genuine Pomona 5250 clip | ~$35 | works; watch voltage yourself. `-p serprog:dev=COMx` |
| Pro | Dediprog SF100 / Glasgow | $139–275 | in-system reset-hold pins; WSON/QFN packages |

**Genuine clips matter** — clone clips are the #1 cause of unstable reads. WSON/QFN
packages need a different clip or a socket adapter.

## CH341A specifics (read this before you clip)
1. **Voltage — the one that can damage the chip.** Most CH341A "black" boards drive the
   SPI pins at ~**5 V** even though BIOS flash is **3.3 V**. Reading is lower-risk than
   writing, but 5 V on a 3.3 V part can still stress/damage it. Options, best first:
   use a **3.3 V-modded board** (the "pin-28 lift" / trace-cut mod, widely documented) or
   an inline **level shifter**; or accept the risk on a spare/expendable target. If in
   doubt, spend the extra for a Tigard.
2. **Windows driver — flashrom needs WinUSB.** The stock CH341 driver won't let flashrom
   talk to the board. Use **[Zadig](https://zadig.akeo.ie/)** to replace the CH341A's
   driver with **WinUSB (libusb)**. (Do this while the CH341A is plugged in, target NOT
   connected.) Then flashrom sees it as `ch341a_spi`.
3. It's **USB 1.1 → slow**; a 16 MB read takes a few minutes. That's fine.
4. Clip pin-1 (the dot) to the flash chip's pin-1 (the dot). Wrong orientation = garbage.

Then read (target powered OFF):
```powershell
.\read\Read-ExternalSPI.ps1 -Programmer ch341a_spi -Out spi-dump.bin
```
or raw: `flashrom -p ch341a_spi -r r1.bin`  (auto-detects the chip; if not, add `-c <chip>`).

## Procedure (powered-off, sequential)
1. **Power the machine OFF** and unplug it. The trustworthy read is done with the host
   not driving the bus (a live host contends for the bus and back-powers the board
   through the flash rail — a real hazard and a source of garbage reads).
2. Clip onto the BIOS SPI flash chip (an 8-pin SOIC, usually near the CMOS battery).
3. Read it **three times** and confirm the hashes match (stability = a good read; a
   mismatch means contention or a bad clip, not evidence). The helper does this:
   ```powershell
   .\read\Read-ExternalSPI.ps1 -Programmer ft2232_spi:type=232H -Out spi-dump.bin
   ```
   or raw flashrom: `flashrom -p ft2232_spi:type=232H -r r1.bin` (×3, compare).
4. **Diff against the corpus** — this is the verdict:
   ```
   python -m corpus check spi-dump.bin --vendor Gigabyte --model "B450M DS3H" \
       --version F50 --read external
   ```
   `--read external` tells SPI-Eyes the read is trustworthy: a full match against a
   clean-capable (vendor-signed / coreboot) reference then earns **CLEAN (Above-SMM)**.
   Any modified / missing / added module -> **ANOMALOUS**, named line-by-line.

## Honest limits
- The external read covers the **SPI flash** (UEFI BIOS + ME/PSP + option ROMs). It does
  NOT cover device-resident firmware (GPU/NIC/SSD-controller) — those need their own reads.
- CLEAN is "Above-SMM": DRTM does not measure SMM, so unconditional CLEAN also wants SMM
  locks validated (R1). The external read is nonetheless the strongest evidence available.
- Sequential, not live: software read now, power down, external read, diff offline. There
  is no trustworthy *simultaneous* compare.
