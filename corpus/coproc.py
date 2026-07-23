"""Coprocessor firmware parsers: AMD PSP ($PSP) and Intel ME/CSME ($FPT).

These live in the SAME SPI flash as the BIOS, so the image we already carve for
UEFI also contains them -- we just weren't parsing them. This promotes ME/PSP from
a whole-image blob to per-entry hashes (bootloader, SMU, keys, FTPR, NFTP, ...),
the same per-component granularity we get for UEFI modules.

Zero-dependency, bounds-checked, never raises. Not a full ME/PSP reverse-engineer
(that's MEAnalyzer / PSPTool); we enumerate the top-level directory/partition table
and hash each entry -- enough for known-good matching.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

# AMD PSP directory entry types (low byte of the type field) -- common subset
PSP_TYPES = {
    0x00: "AMD_PUBLIC_KEY", 0x01: "PSP_BOOTLOADER", 0x02: "PSP_TRUSTED_OS",
    0x03: "PSP_RECOVERY_BOOTLOADER", 0x08: "SMU_FIRMWARE", 0x09: "AMD_SEC_DBG_KEY",
    0x0A: "OEM_PSP_FW_KEY", 0x0B: "SOFT_FUSE", 0x0C: "PSP_TRUSTED_OS_2",
    0x12: "SMU_FIRMWARE_2", 0x1A: "PSP_DIR_L2", 0x21: "WRAPPED_IKEK",
    0x24: "SEC_GASKET", 0x28: "MP2_FW", 0x2A: "DRIVER_ENTRIES", 0x30: "AGESA_0",
    0x40: "PSP_DIR_L2_2", 0x62: "BIOS_DIR", 0x63: "AGESA_APOB",
}
# Intel ME FPT partition names are 4-char ASCII (FTPR, NFTP, MFS, ...) -- no fixed map needed


@dataclass
class CoEntry:
    kind: str            # "AMD-PSP" | "Intel-ME"
    name: str            # type name / partition name
    type_id: int
    offset: int
    size: int
    sha256: Optional[str]
    note: str = ""


@dataclass
class CoResult:
    kind: Optional[str] = None
    entries: List[CoEntry] = field(default_factory=list)
    error: Optional[str] = None


def parse(data: bytes) -> CoResult:
    """Detect and parse whichever coprocessor firmware is present."""
    try:
        if data.find(b"$PSP") >= 0 or data.find(b"$PL2") >= 0:
            return CoResult(kind="AMD-PSP", entries=parse_amd_psp(data))
        if data.find(b"$FPT") >= 0:
            return CoResult(kind="Intel-ME", entries=parse_intel_me(data))
        return CoResult(kind=None, error="no $PSP/$FPT signature found")
    except Exception as e:  # noqa: BLE001
        return CoResult(error=f"{type(e).__name__}: {e}")


def parse_amd_psp(data: bytes) -> List[CoEntry]:
    n = len(data)
    idx = data.find(b"$PSP")
    if idx < 0:
        idx = data.find(b"$PL2")
    if idx < 0:
        return []
    num = struct.unpack_from("<I", data, idx + 8)[0]
    if not (0 < num <= 512):
        return []
    mask = (n - 1) if (n & (n - 1)) == 0 else 0xFFFFFF  # flash is mem-mapped at the top
    out: List[CoEntry] = []
    base = idx + 16
    for i in range(num):
        off = base + i * 16
        if off + 16 > n:
            break
        etype, size, addr = struct.unpack_from("<IIQ", data, off)
        name = PSP_TYPES.get(etype & 0xFF, f"0x{etype & 0xFF:02X}")
        loc = addr & mask
        if 0 < size < n and loc + size <= n:
            h = hashlib.sha256(data[loc:loc + size]).hexdigest()
            out.append(CoEntry("AMD-PSP", name, etype & 0xFF, loc, size, h))
        else:
            out.append(CoEntry("AMD-PSP", name, etype & 0xFF, loc, size, None, note="unresolved addr/size"))
    return out


def parse_intel_me(data: bytes) -> List[CoEntry]:
    n = len(data)
    sig = data.find(b"$FPT")
    if sig < 0:
        return []
    # $FPT header: marker(4) NumPartitions(u32) then version/flags; entries start at header+0x20
    num = struct.unpack_from("<I", data, sig + 4)[0]
    if not (0 < num <= 256):
        return []
    out: List[CoEntry] = []
    ent = sig + 0x20
    for i in range(num):
        off = ent + i * 32
        if off + 32 > n:
            break
        name = data[off:off + 4].decode("ascii", "replace").rstrip("\x00")
        p_off, p_size = struct.unpack_from("<II", data, off + 0x18)
        if not name.isprintable() or not name.strip():
            continue
        if 0 < p_size < n and p_off + p_size <= n:
            h = hashlib.sha256(data[p_off:p_off + p_size]).hexdigest()
            out.append(CoEntry("Intel-ME", name, 0, p_off, p_size, h))
        else:
            out.append(CoEntry("Intel-ME", name, 0, p_off, p_size, None, note="unresolved offset/size"))
    return out
