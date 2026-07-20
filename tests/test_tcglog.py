"""Deterministic tests for the TCG event-log parser + PCR reconstruction.

Uses a hand-built synthetic crypto-agile log (single SHA-256 bank) so the expected
PCR values are computed independently with hashlib. No machine data involved.
"""
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attest.tcglog import parse, EV_NO_ACTION  # noqa: E402

SHA256_ALG_ID = 0x000B
EV_SEPARATOR = 0x00000004
EV_EVENT_TAG = 0x00000006


def _spec_id_event(alg_id=SHA256_ALG_ID, digest_size=32) -> bytes:
    return (b"Spec ID Event03\x00"
            + struct.pack("<I", 0)            # platformClass
            + bytes([0, 2, 0, 2])             # minor, major, errata, uintnSize
            + struct.pack("<I", 1)            # numberOfAlgorithms
            + struct.pack("<HH", alg_id, digest_size)
            + bytes([0]))                     # vendorInfoSize


def _rec0(spec: bytes) -> bytes:
    # legacy TCG_PCR_EVENT: pcr(4) type(4) sha1(20) size(4) event
    return (struct.pack("<II", 0, EV_NO_ACTION) + (b"\x00" * 20)
            + struct.pack("<I", len(spec)) + spec)


def _rec2(pcr: int, etype: int, digest: bytes, body: bytes) -> bytes:
    # TCG_PCR_EVENT2: pcr(4) type(4) count(4) [algId(2) digest] size(4) body
    return (struct.pack("<III", pcr, etype, 1)
            + struct.pack("<H", SHA256_ALG_ID) + digest
            + struct.pack("<I", len(body)) + body)


def build_log(measurements):
    """measurements: list of (pcr, etype, digest_bytes, body_bytes)."""
    out = _rec0(_spec_id_event())
    for (pcr, etype, digest, body) in measurements:
        out += _rec2(pcr, etype, digest, body)
    return out


def test_parses_clean_no_trailing():
    d1 = b"\x11" * 32
    d2 = b"\x22" * 32
    log = build_log([(0, EV_SEPARATOR, d1, b"\x00\x00\x00\x00"),
                     (0, EV_EVENT_TAG, d2, b"tag")])
    r = parse(log)
    assert r.ok, r.error
    assert r.trailing_bytes == 0
    assert r.algorithms == {"sha256": 32}
    assert len(r.events) == 3  # spec-id + 2


def test_pcr_reconstruction_matches_hashlib():
    d1 = b"\x11" * 32
    d2 = b"\x22" * 32
    log = build_log([(0, EV_SEPARATOR, d1, b""),
                     (0, EV_EVENT_TAG, d2, b"")])
    r = parse(log)
    # independent expected value: extend twice from all-zero
    expected = hashlib.sha256(b"\x00" * 32 + d1).digest()
    expected = hashlib.sha256(expected + d2).digest()
    assert r.pcrs["sha256"][0] == expected.hex()


def test_no_action_not_extended():
    d1 = b"\x33" * 32
    # an EV_NO_ACTION record must NOT change the PCR
    log = build_log([(7, EV_NO_ACTION, d1, b""),
                     (7, EV_SEPARATOR, d1, b"")])
    r = parse(log)
    expected = hashlib.sha256(b"\x00" * 32 + d1).digest().hex()  # only the separator extends
    assert r.pcrs["sha256"][7] == expected


def test_truncated_is_not_ok_but_does_not_raise():
    r = parse(b"\x00" * 8)
    assert r.ok is False
    assert r.error


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all tcglog tests passed")


if __name__ == "__main__":
    _run()
