"""TCG event-log parser + PCR reconstruction  (SPI-Eyes Phase 2 foundation).

Parses a Windows WBCL / TCG PC Client crypto-agile event log (the format emitted by
`C:\\Windows\\Logs\\MeasuredBoot\\*.log` and by TBS `Tbsi_Get_TCG_Log_Ex`), and
recomputes the PCR values the log *claims* to produce.

This is the core of the earned-CLEAN engine's mandatory event-log cross-check
(WHITEPAPER R2): a DRTM/TPM quote is only trusted when the event log independently
reconstructs the quoted PCRs AND each measured component hashes to a known-good
reference. This module does the reconstruction half; it is verification machinery,
never a trust anchor by itself.

Format (TCG PC Client Platform Firmware Profile):
  * Record 0 is a legacy TCG_PCR_EVENT (SHA1-shaped) whose event body is a
    TCG_EfiSpecIdEvent declaring the crypto-agile algorithm set.
  * Records 1..n are TCG_PCR_EVENT2 (TPML_DIGEST_VALUES, multi-bank).

Safety: parsing is bounds-checked and never raises on malformed input; it returns a
ParseResult with `ok=False` and an `error` instead. Untrusted input is expected.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# TPM_ALG_ID -> (name, digest_size)
ALG: Dict[int, tuple] = {
    0x0004: ("sha1", 20), 0x000B: ("sha256", 32), 0x000C: ("sha384", 48),
    0x000D: ("sha512", 64), 0x0012: ("sm3_256", 32),
}
_HASH = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
         "sha384": hashlib.sha384, "sha512": hashlib.sha512}

EV_NO_ACTION = 0x00000003

EVENT_TYPES: Dict[int, str] = {
    0x00000000: "EV_PREBOOT_CERT", 0x00000001: "EV_POST_CODE", 0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR", 0x00000005: "EV_ACTION", 0x00000006: "EV_EVENT_TAG",
    0x00000007: "EV_S_CRTM_CONTENTS", 0x00000008: "EV_S_CRTM_VERSION",
    0x00000009: "EV_CPU_MICROCODE", 0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
    0x0000000B: "EV_TABLE_OF_DEVICES", 0x0000000C: "EV_COMPACT_HASH", 0x0000000D: "EV_IPL",
    0x0000000E: "EV_IPL_PARTITION_DATA", 0x0000000F: "EV_NONHOST_CODE",
    0x00000010: "EV_NONHOST_CONFIG", 0x00000011: "EV_NONHOST_INFO",
    0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG", 0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION", 0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER", 0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION", 0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES", 0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2", 0x8000000C: "EV_EFI_VARIABLE_BOOT2",
    0x80000010: "EV_EFI_HCRTM_EVENT", 0x80000011: "EV_EFI_VARIABLE_AUTHORITY",
    0x80000012: "EV_EFI_VARIABLE_AUTHORITY", 0x80000020: "EV_EFI_SPDM_FIRMWARE_BLOB",
    0x80000021: "EV_EFI_SPDM_FIRMWARE_CONFIG",
}


def event_type_name(t: int) -> str:
    return EVENT_TYPES.get(t, f"0x{t:08X}")


@dataclass
class LogEvent:
    index: int
    pcr: int
    event_type: int
    event_type_name: str
    digests: Dict[str, str]          # alg_name -> hex digest
    event_size: int
    event_summary: str               # short ASCII/hex preview of the event body
    measured: bool                   # False for EV_NO_ACTION (not extended into a PCR)


@dataclass
class ParseResult:
    ok: bool
    algorithms: Dict[str, int] = field(default_factory=dict)   # name -> digest_size
    events: List[LogEvent] = field(default_factory=list)
    pcrs: Dict[str, Dict[int, str]] = field(default_factory=dict)  # alg -> {pcr: hex}
    trailing_bytes: int = 0
    error: Optional[str] = None


def _summary(body: bytes) -> str:
    # ASCII if mostly printable, else short hex
    try:
        txt = body.split(b"\x00", 1)[0].decode("ascii")
        if txt and all(32 <= ord(c) < 127 for c in txt):
            return txt[:48]
    except Exception:  # noqa: BLE001
        pass
    return body[:16].hex() + ("..." if len(body) > 16 else "")


def parse(data: bytes) -> ParseResult:
    n = len(data)
    if n < 32:
        return ParseResult(ok=False, error="log too short for a TCG_PCR_EVENT header")
    try:
        return _parse(data, n)
    except Exception as e:  # noqa: BLE001  (never raise on untrusted input)
        return ParseResult(ok=False, error=f"{type(e).__name__}: {e}")


def _parse(data: bytes, n: int) -> ParseResult:
    off = 0
    # --- record 0: legacy TCG_PCR_EVENT carrying the Spec ID header ---
    pcr, etype = struct.unpack_from("<II", data, off)
    ev_size = struct.unpack_from("<I", data, off + 28)[0]
    spec_body = data[off + 32: off + 32 + ev_size]
    off += 32 + ev_size

    algs = _parse_spec_id(spec_body)
    if not algs:
        return ParseResult(ok=False, error="no crypto-agile Spec ID header (algorithm set unknown)")
    alg_by_id = {aid: ALG[aid] for aid in algs if aid in ALG}
    algorithms = {name: size for (name, size) in alg_by_id.values()}

    events: List[LogEvent] = []
    pcrs: Dict[str, Dict[int, str]] = {name: {} for name in algorithms}

    idx = 0
    # record 0 itself is EV_NO_ACTION (Spec ID) -> informational, not extended
    events.append(LogEvent(idx, pcr, etype, event_type_name(etype), {}, ev_size,
                           _summary(spec_body), measured=False))

    # --- records 1..n: TCG_PCR_EVENT2 ---
    while off + 8 <= n:
        idx += 1
        pcr, etype = struct.unpack_from("<II", data, off)
        p = off + 8
        count = struct.unpack_from("<I", data, p)[0]
        p += 4
        digests: Dict[str, str] = {}
        for _ in range(count):
            alg_id = struct.unpack_from("<H", data, p)[0]
            p += 2
            if alg_id not in ALG:
                # unknown alg: we cannot know its digest size -> bail cleanly
                return ParseResult(ok=False, algorithms=algorithms, events=events, pcrs=pcrs,
                                   error=f"unknown alg id 0x{alg_id:04x} at event {idx}")
            name, size = ALG[alg_id]
            digests[name] = data[p:p + size].hex()
            p += size
        ev_size = struct.unpack_from("<I", data, p)[0]
        p += 4
        body = data[p:p + ev_size]
        p += ev_size

        measured = etype != EV_NO_ACTION
        events.append(LogEvent(idx, pcr, etype, event_type_name(etype), digests, ev_size,
                               _summary(body), measured))
        if measured:
            _extend(pcrs, pcr, digests, algorithms)
        off = p

    trailing = n - off
    return ParseResult(ok=True, algorithms=algorithms, events=events, pcrs=pcrs,
                       trailing_bytes=trailing,
                       error=(None if trailing == 0 else f"{trailing} trailing byte(s) after last event"))


def _parse_spec_id(body: bytes):
    """Return list of algorithm ids declared in a TCG_EfiSpecIdEvent, or [] if absent."""
    if len(body) < 16 or not body.startswith(b"Spec ID Event03"):
        return []
    # signature(16) platformClass(4) minor(1) major(1) errata(1) uintnSize(1) numAlgs(4)
    p = 16 + 4 + 1 + 1 + 1 + 1
    num = struct.unpack_from("<I", body, p)[0]
    p += 4
    ids = []
    for _ in range(num):
        alg_id, _dsize = struct.unpack_from("<HH", body, p)
        ids.append(alg_id)
        p += 4
    return ids


def _extend(pcrs: Dict[str, Dict[int, str]], pcr: int, digests: Dict[str, str],
            algorithms: Dict[str, int]) -> None:
    """PCR[pcr] = HASH(PCR[pcr] || digest) for each bank present."""
    for name, size in algorithms.items():
        if name not in _HASH or name not in digests:
            continue
        cur = bytes.fromhex(pcrs[name].get(pcr, "00" * size))
        new = digests[name]
        pcrs[name][pcr] = _HASH[name](cur + bytes.fromhex(new)).hexdigest()


def reconstruct_pcrs(data: bytes) -> Dict[str, Dict[int, str]]:
    """Convenience: parse and return only the reconstructed PCR map."""
    return parse(data).pcrs
