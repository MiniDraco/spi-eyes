# Software (internal) read — no hardware, no clip

An external read (a clip on the chip) is the only path to an **earned CLEAN**, because a
software read can be lied to by a resident ring -2/-3 implant. If you're skipping hardware,
a **software internal read** still gets you a real dump to line-check against the corpus —
it just caps at **CANNOT-VERIFY** (on a match) or **ANOMALOUS** (on a deviation), never
CLEAN. That's still worth doing: the commodity / inherited implant tier mostly does NOT
stealth against a scanner, so this catches the real-world threats. It cannot catch a
top-tier implant that actively feeds a clean image.

## Recommended: Linux live-USB + flashrom internal (non-invasive)
Reads the flash through the **chipset's own SPI controller** — no external programmer, and
nothing is installed on the target (it runs from RAM).

1. Write a Linux live-USB (Ubuntu, Fedora, etc.). Boot the target from it ("Try", don't install).
2. `sudo apt install flashrom`  (or `dnf install flashrom`).
3. `sudo flashrom -p internal -r dump.bin`
   - If it complains about multiple chip candidates, add `-c <chip>` from the list it prints.
   - Regions the host CPU is denied (often the **ME region reads back as all-`0xFF`**) are a
     *denied read*, not "empty" — our tooling treats that as CANNOT-VERIFY, never clean.
4. Copy `dump.bin` off the USB, then line-check it:
   ```
   python -m corpus check dump.bin --vendor Gigabyte --model "B450M DS3H" \
       --version F50 --read software
   ```
   `--read software` tells SPI-Eyes the read is blindable → the best a full match earns is
   **CANNOT-VERIFY**; any modified / missing / added module is still **ANOMALOUS**, named.

## Windows alternative: CHIPSEC (heavier — modifies the system)
`chipsec_util spi dump rom.bin` reads SPI via CHIPSEC's kernel driver. On Windows this
means building/signing/loading an unsigned kernel driver (needs HVCI off, and the load is
observable to a resident implant). Prefer the Linux live-USB route unless you already run
CHIPSEC.

## What the result means (honest ceiling)
- **Full match, `--read software`** → CANNOT-VERIFY. You did not prove clean; you proved
  *no non-stealthed implant was found and the read wasn't obviously blinded*. To earn CLEAN,
  you need an external read (`read/README.md`) or a DRTM TPM quote (Secured-core hardware).
- **Any deviation** → ANOMALOUS, line-by-line — a real finding, worth investigating.
- **Denied/`0xFF` regions** → CANNOT-VERIFY for those regions, never counted as clean.
