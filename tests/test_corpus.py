"""Deterministic tests for the firmware carver + reference manifest + line matcher.

Builds tiny but real UEFI Firmware Volumes in-memory (proper FV + FFS headers) so
the carver, manifest, and matcher are exercised end-to-end without external data.
"""
import struct
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from corpus.uefifv import carve                                   # noqa: E402
from corpus.manifest import build_manifest, match                # noqa: E402

FFS2 = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le
G1 = uuid.UUID("11111111-1111-1111-1111-111111111111").bytes_le
G2 = uuid.UUID("22222222-2222-2222-2222-222222222222").bytes_le
G3 = uuid.UUID("33333333-3333-3333-3333-333333333333").bytes_le
T_DRIVER = 0x07
T_RAW = 0x01


def ffs(guid16, ftype, body):
    total = 24 + len(body)
    hdr = (guid16 + b"\x00\x00" + bytes([ftype]) + b"\x00"
           + bytes([total & 0xFF, (total >> 8) & 0xFF, (total >> 16) & 0xFF]) + b"\xf8")
    f = hdr + body
    return f + b"\xff" * ((-len(f)) % 8)  # pad to 8-byte alignment


def fv(files):
    body = b"".join(files)
    hdrlen = 0x48
    fvlen = hdrlen + len(body)
    header = (b"\x00" * 16 + FFS2 + struct.pack("<Q", fvlen) + b"_FVH"
              + struct.pack("<I", 0) + struct.pack("<H", hdrlen) + struct.pack("<H", 0)
              + struct.pack("<H", 0) + b"\x00" + b"\x02"
              + struct.pack("<II", 1, fvlen) + struct.pack("<II", 0, 0))
    assert len(header) == hdrlen
    return header + body


def test_carve_finds_files_and_classifies():
    img = fv([ffs(G1, T_DRIVER, b"driver-one-code"),
              ffs(G2, T_DRIVER, b"driver-two-code"),
              ffs(G3, T_RAW, b"config-data")])
    r = carve(img)
    assert r.ok
    assert len(r.all_files) == 3
    code = [f for f in r.all_files if f.is_code]
    assert len(code) == 2                       # RAW is data, not code


def test_manifest_and_self_match():
    img = fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"bbb"), ffs(G3, T_RAW, b"cfg")])
    m = build_manifest(carve(img))
    assert m["code_module_count"] == 2
    r = match(carve(img), m)
    assert r.matched == 2 and r.anomalies == 0
    assert r.content_verdict == "CONTENT-MATCH"


def test_detects_modified_module():
    ref = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"bbb")])))
    tampered = carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"XXX")]))
    r = match(tampered, ref)
    assert r.matched == 1
    assert len(r.mismatched) == 1
    assert r.content_verdict == "ANOMALOUS"


def test_detects_missing_module():
    ref = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"bbb")])))
    r = match(carve(fv([ffs(G1, T_DRIVER, b"aaa")])), ref)
    assert len(r.missing) == 1 and r.content_verdict == "ANOMALOUS"


def test_detects_added_module():
    ref = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa")])))
    r = match(carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"new")])), ref)
    assert len(r.extra) == 1 and r.content_verdict == "ANOMALOUS"


def test_clean_capable_tier_flag():
    m = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa")])),
                       source={"trust_tier": "vendor-signed"})
    r = match(carve(fv([ffs(G1, T_DRIVER, b"aaa")])), m)
    assert r.clean_capable_tier is True
    m2 = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa")])),
                        source={"trust_tier": "consensus"})
    r2 = match(carve(fv([ffs(G1, T_DRIVER, b"aaa")])), m2)
    assert r2.clean_capable_tier is False       # consensus never earns CLEAN (R3)


def test_corpus_index_is_version_exact():
    import json
    import os
    import tempfile
    from corpus.index import CorpusIndex
    d = tempfile.mkdtemp()
    for ver in ("F40", "F50"):
        with open(os.path.join(d, f"g_{ver}.json"), "w", encoding="utf-8") as fh:
            json.dump({"source": {"vendor": "Gigabyte", "model": "B450M DS3H",
                                  "version": ver, "trust_tier": "vendor-signed"},
                       "code_module_count": 10, "modules": []}, fh)
    idx = CorpusIndex(d)
    assert idx.lookup("gigabyte", "b450m ds3h", "f50") is not None       # normalized keys
    assert idx.lookup("Gigabyte", "B450M DS3H", "F50") is not None
    # an uncovered version must return None -- NEVER match against a different version
    assert idx.lookup("Gigabyte", "B450M DS3H", "F42") is None
    assert set(idx.versions_for("Gigabyte", "B450M DS3H")) == {"F40", "F50"}


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all corpus tests passed")


if __name__ == "__main__":
    _run()
