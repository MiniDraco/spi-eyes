"""Minimal, zero-dependency UEFI Firmware Volume / FFS carver.

Carves a raw UEFI firmware image (or the BIOS region of an SPI dump) into its
component files -- the granularity SPI-Eyes matches "line by line" against a
known-good reference. For each FFS file we record: GUID, type, size, and SHA-256
of the file body. Immutable *code* files (PEI/DXE/SMM modules, drivers) are the
ones that must byte-match a vendor reference; variable data (raw/freeform/pad,
NVRAM) is normalized out of the match.

Format refs: PI spec EFI_FIRMWARE_VOLUME_HEADER + EFI_FFS_FILE_HEADER (+ FFS2).
This is not a full UEFI parser (it does not descend into sections); file-level
GUID+hash is the reference unit. Section-level / vendor-wrapper unwrapping
(Dell PFS, Insyde, ME/PSP) are added by dedicated carvers later.

Parsing is bounds-checked and never raises on malformed input.
"""
from __future__ import annotations

import hashlib
import lzma
import struct
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

FV_SIGNATURE = b"_FVH"  # located at offset 40 in EFI_FIRMWARE_VOLUME_HEADER
# EFI_SECTION_GUID_DEFINED payload compressed with LZMA (EDK2 LzmaCustomDecompress)
LZMA_SECTION_GUID = "ee4e5898-3914-4259-9d6e-dc7bd79403cf"
# EFI_FIRMWARE_FILE_SYSTEM{,2,3}_GUID -- only these FVs hold FFS files (not NVRAM etc.)
FFS_GUIDS = {
    "7a9354d9-0468-444a-81ce-0bf617d890df",   # FFS1
    "8c8ce578-8a3d-4f1c-9935-896185c32dd3",   # FFS2
    "5473c07a-3dcb-4dca-bd6f-1e9689e7349a",   # FFS3
}
_MAX_DEPTH = 8

# EFI_FV_FILETYPE
FILETYPES = {
    0x01: "RAW", 0x02: "FREEFORM", 0x03: "SECURITY_CORE", 0x04: "PEI_CORE",
    0x05: "DXE_CORE", 0x06: "PEIM", 0x07: "DRIVER", 0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION", 0x0A: "MM", 0x0B: "FIRMWARE_VOLUME_IMAGE",
    0x0C: "COMBINED_MM_DXE", 0x0D: "MM_CORE", 0x0E: "MM_STANDALONE",
    0x0F: "MM_CORE_STANDALONE", 0xF0: "FFS_PAD",
}
# file types that are immutable executable code -> must match a reference hash
CODE_TYPES = {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F}


@dataclass
class FfsFile:
    guid: str
    type_id: int
    type_name: str
    offset: int          # offset within its containing buffer
    size: int            # total file size (incl. header)
    body_sha256: str     # sha256 of the file body (header excluded)
    is_code: bool
    depth: int = 0       # 0 = top-level image; >0 = inside a decompressed volume
    _body: bytes = field(default=b"", repr=False, compare=False)


@dataclass
class Fv:
    offset: int
    fs_guid: str
    length: int
    files: List[FfsFile] = field(default_factory=list)


@dataclass
class CarveResult:
    ok: bool
    image_sha256: str
    fvs: List[Fv] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def all_files(self) -> List[FfsFile]:
        return [f for fv in self.fvs for f in fv.files]


def _guid(b: bytes) -> str:
    # EFI GUID is little-endian for the first three fields; uuid handles that.
    try:
        return str(uuid.UUID(bytes_le=b[:16]))
    except Exception:  # noqa: BLE001
        return b[:16].hex()


def carve(data: bytes) -> CarveResult:
    img_hash = hashlib.sha256(data).hexdigest()
    try:
        fvs: List[Fv] = []
        _carve_recursive(data, fvs, depth=0)
        return CarveResult(ok=True, image_sha256=img_hash, fvs=fvs)
    except Exception as e:  # noqa: BLE001  (untrusted input must never crash us)
        return CarveResult(ok=False, image_sha256=img_hash, error=f"{type(e).__name__}: {e}")


def _carve_recursive(data: bytes, fvs: List[Fv], depth: int) -> None:
    if depth > _MAX_DEPTH:
        return
    found = _find_fvs(data, depth)
    fvs.extend(found)
    for fv in found:
        for f in fv.files:
            for blob in _decompress_sections(f._body):
                _carve_recursive(blob, fvs, depth + 1)


def _decompress_sections(body: bytes) -> List[bytes]:
    """Yield decompressed / nested-FV payloads found in an FFS file's sections."""
    out: List[bytes] = []
    off, n = 0, len(body)
    while off + 4 <= n:
        size = body[off] | (body[off + 1] << 8) | (body[off + 2] << 16)
        stype = body[off + 3]
        hdr = 4
        if size == 0xFFFFFF:                       # SECTION2 extended size
            if off + 8 > n:
                break
            size = struct.unpack_from("<I", body, off + 4)[0]
            hdr = 8
        if size < hdr or off + size > n:
            break
        sec = body[off + hdr: off + size]
        try:
            if stype == 0x02 and len(sec) >= 20:          # GUID_DEFINED
                guid = _guid(sec[0:16])
                data_off = struct.unpack_from("<H", sec, 16)[0]
                payload = body[off + data_off: off + size]
                if guid == LZMA_SECTION_GUID:
                    out.append(lzma.decompress(payload, format=lzma.FORMAT_ALONE))
            elif stype == 0x01 and len(sec) >= 5:         # COMPRESSION (try LZMA)
                try:
                    out.append(lzma.decompress(sec[5:], format=lzma.FORMAT_ALONE))
                except Exception:  # noqa: BLE001  (Tiano/standard EFI comp not handled)
                    pass
            elif stype == 0x17:                           # FIRMWARE_VOLUME_IMAGE
                out.append(sec)
        except Exception:  # noqa: BLE001
            pass
        off = (off + size + 3) & ~3  # sections are 4-byte aligned
    return out


def _find_fvs(data: bytes, depth: int = 0) -> List[Fv]:
    n = len(data)
    fvs: List[Fv] = []
    seen = set()
    pos = 0
    while True:
        i = data.find(FV_SIGNATURE, pos)
        if i < 0:
            break
        pos = i + 4
        fv_start = i - 40  # signature sits at offset 40 of the FV header
        if fv_start < 0 or fv_start in seen:
            continue
        # EFI_FIRMWARE_VOLUME_HEADER: ZeroVector(16) FileSystemGuid(16) FvLength(u64)
        #   Signature(4) Attributes(4) HeaderLength(u16) Checksum(u16) ...
        try:
            fs_guid = _guid(data[fv_start + 16: fv_start + 32])
            fv_len = struct.unpack_from("<Q", data, fv_start + 32)[0]
            hdr_len = struct.unpack_from("<H", data, fv_start + 48)[0]
        except struct.error:
            continue
        if fv_len < hdr_len or fv_len > n - fv_start or hdr_len < 56 or fv_len < 64:
            continue
        seen.add(fv_start)
        fv = Fv(offset=fv_start, fs_guid=fs_guid, length=fv_len)
        if fs_guid in FFS_GUIDS:  # NVRAM/varstore FVs hold data, not FFS files
            _walk_ffs(data, fv_start, fv_start + hdr_len, fv_start + fv_len, fv, depth)
        fvs.append(fv)
    return fvs


def _walk_ffs(data: bytes, fv_start: int, start: int, end: int, fv: Fv, depth: int = 0) -> None:
    off = (start + 7) & ~7  # 8-byte aligned
    while off + 24 <= end:
        # EFI_FFS_FILE_HEADER: Name(16) IntegrityCheck(2) Type(1)@+18
        #   Attributes(1)@+19 Size[3]@+20..22 State(1)@+23
        ftype = data[off + 18]
        attrib = data[off + 19]
        size24 = data[off + 20] | (data[off + 21] << 8) | (data[off + 22] << 16)
        # true free space = erased header (type AND size all 0xFF). NOTE a pad file
        # (type 0xF0) also has an all-0xFF *name* GUID -> do NOT key off the name.
        if ftype == 0xFF and size24 == 0xFFFFFF:
            break
        hdr = 24
        if attrib & 0x01 and size24 == 0xFFFFFF:  # FFS2 large file (ext size)
            total = struct.unpack_from("<Q", data, off + 24)[0]
            hdr = 32
        else:
            total = size24
        if total < hdr or off + total > end:
            break
        if ftype == 0xF0:  # FFS_PAD -- alignment filler, skip past it
            off = (off + total + 7) & ~7
            continue
        name = _guid(data[off: off + 16])
        body = data[off + hdr: off + total]
        fv.files.append(FfsFile(
            guid=name, type_id=ftype, type_name=FILETYPES.get(ftype, f"0x{ftype:02X}"),
            offset=off, size=total, body_sha256=hashlib.sha256(body).hexdigest(),
            is_code=(ftype in CODE_TYPES), depth=depth, _body=body))
        off = (off + total + 7) & ~7
