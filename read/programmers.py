"""SPI programmer registry -- pick your hardware, we hand flashrom the right string.

We do NOT reimplement a driver per programmer: flashrom already abstracts ~50 of them
behind `flashrom -p <name>`. This is a curated registry of the popular ones with their
flashrom identifier + the quirks that actually bite (voltage, Windows driver, OS). We
never need to own the hardware to add one -- only its public docs.

  python read/programmers.py            # list them
  python read/programmers.py ch341a     # look one up

Source of truth for the full list + exact syntax: `flashrom --help` / flashrom.org.
"""
from __future__ import annotations

import sys

# name | flashrom -p string | ~cost | os | notes/quirks
REGISTRY = [
    ("internal",        "internal",                       "$0",   "linux",  "software chipset read, NO external hw; blindable -> CANNOT-VERIFY. Live-USB flashrom."),
    ("ch341a",          "ch341a_spi",                     "$5",   "all",    "5V-on-3.3V hazard: do pin-28/level-shift mod. Windows: Zadig WinUSB. USB1.1 (slow)."),
    ("ch347",           "ch347_spi",                      "$10",  "all",    "CH341 successor: 3.3V-safe, USB2 (faster). Needs a recent flashrom."),
    ("tigard",          "ft2232_spi:type=232H",           "$39",  "all",    "FT2232H, proper level-shifting. RECOMMENDED external reader."),
    ("ft232h",          "ft2232_spi:type=232H",           "$15",  "all",    "Adafruit/generic FT232H. Mind voltage yourself."),
    ("ft2232h-mini",    "ft2232_spi:type=2232H,port=A",   "$20",  "all",    "Generic FT2232H module; no built-in level shift."),
    ("ft4232h",         "ft2232_spi:type=4232H,port=A",   "$30",  "all",    "Quad FT4232H module."),
    ("pi-pico",         "serprog:dev=COMx:115200",        "$4",   "all",    "Flash pico-serprog UF2. USB-CDC (set your COM). Watch voltage."),
    ("raspberry-pi",    "linux_spi:dev=/dev/spidev0.0,spispeed=1000", "$0", "linux", "Pi GPIO SPI. Bump GPIO drive strength for cables."),
    ("bus-pirate",      "buspirate_spi:dev=COMx",         "$30",  "all",    "Bus Pirate v3/v4. Multi-protocol; slower SPI."),
    ("dediprog-sf100",  "dediprog:device=SF100",          "$275", "all",    "Turnkey pro reader; in-system reset-hold pins. Best Windows GUI too."),
    ("dediprog-sf600",  "dediprog:device=SF600",          "$450", "all",    "Faster/higher-density Dediprog."),
    ("stlink-v3",       "stlinkv3_spi",                   "$25",  "all",    "ST-Link V3 in SPI mode."),
    ("jlink",           "jlink_spi",                      "varies","all",   "Segger J-Link SPI."),
    ("serprog-arduino", "serprog:dev=COMx:115200",        "$10",  "all",    "frser-duino on an Arduino/Teensy as a serprog reader."),
    ("beaglebone",      "linux_spi:dev=/dev/spidev0.0",   "$0",   "linux",  "BeagleBone SPI (if you have one)."),
    ("rayer",           "rayer_spi",                      "$5",   "all",    "Legacy parallel-port bit-bang cable. Old PCs only."),
    ("dirtyjtag",       "dirtyjtag",                      "$5",   "all",    "STM32-bluepill DirtyJTAG firmware."),
    ("ni-845x",         "ni845x_spi",                     "$$$",  "windows","National Instruments USB-SPI (lab)."),
    ("digilent",        "digilent_spi",                   "$$",   "all",    "Digilent JTAG-SMT2 / analog-discovery SPI."),
]
# Not flashrom programmers (own tooling) -- listed so nobody wonders where they went:
#   Glasgow (glasgow 'memory-25x' applet), Dediprog em100 (SPI EMULATOR, not a reader),
#   spispy (FPGA flash emulator/monitor).


def find(query: str):
    q = query.lower()
    return [r for r in REGISTRY if q in r[0].lower() or q in r[1].lower()]


def main(argv) -> int:
    rows = find(argv[0]) if argv else REGISTRY
    if not rows:
        print(f"no programmer matching {argv[0]!r}. `flashrom --help` lists all ~50.")
        return 1
    print(f"{'name':<16} {'flashrom -p':<38} {'cost':<7} {'os':<7} notes")
    print("-" * 100)
    for name, fr, cost, os_, note in rows:
        print(f"{name:<16} {fr:<38} {cost:<7} {os_:<7} {note}")
    print("\nUse with:  .\\read\\Read-ExternalSPI.ps1 -Programmer '<flashrom -p string>' -Out spi-dump.bin")
    print("Full/authoritative list + exact syntax:  flashrom --help  |  flashrom.org")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
