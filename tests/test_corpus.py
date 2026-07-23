"""Deterministic tests for the firmware carver + reference manifest + line matcher.

Builds tiny but real UEFI Firmware Volumes in-memory (proper FV + FFS headers) so
the carver, manifest, and matcher are exercised end-to-end without external data.
"""
import json
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


def test_corroborate_agree_and_disagree():
    from corpus.corroborate import corroborate
    img = fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"bbb")])
    # 3 identical independent sources -> agree -> corroborated manifest
    r = corroborate([("srcA", img), ("srcB", img), ("srcC", img)],
                    vendor="V", model="M", version="1.0")
    assert r.agree and not r.disagreements
    assert r.manifest["source"]["trust_tier"] == "multi-source-corroborated"
    # one source tampered -> disagreement flagged, no manifest
    bad = fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"HACKED")])
    r2 = corroborate([("srcA", img), ("srcB", img), ("srcC", bad)],
                     vendor="V", model="M", version="1.0")
    assert not r2.agree
    assert any(d["guid"] == "22222222-2222-2222-2222-222222222222" for d in r2.disagreements)
    assert r2.manifest is None


def test_match_manifest_clean_and_anomalous():
    from corpus.manifest import build_manifest, match_manifest
    ref = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"bbb")])),
                         source={"vendor": "V", "model": "M", "version": "1", "trust_tier": "vendor-signed"})
    same = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"bbb")])))
    r = match_manifest(same, ref)
    assert r.all_code_matched and r.clean_capable_tier      # full match + clean-capable tier
    diff = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa"), ffs(G2, T_DRIVER, b"XXX")])))
    r2 = match_manifest(diff, ref)
    assert not r2.all_code_matched and len(r2.mismatched) == 1


def test_unwrap_is_optional_and_graceful():
    from corpus.unwrap import available, unwrap
    assert isinstance(available(), bool)          # optional dep; may or may not be present
    # non-wrapped data must return None (no wrapper matched) and never raise
    assert unwrap(b"this is not a firmware wrapper" * 100) is None


def test_coproc_amd_psp_parse():
    import hashlib
    from corpus.coproc import parse_amd_psp
    n = 0x100000
    buf = bytearray(n)
    payload = b"PSP-BOOTLOADER-CODE" * 12
    buf[0x1000:0x1000 + len(payload)] = payload
    struct.pack_into("<4sIII", buf, 0x2000, b"$PSP", 0, 1, 0)   # cookie, csum, num=1, info
    struct.pack_into("<IIQ", buf, 0x2010, 1, len(payload), 0x1000)  # type=1, size, addr
    entries = parse_amd_psp(bytes(buf))
    assert len(entries) == 1
    assert entries[0].name == "PSP_BOOTLOADER"
    assert entries[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_validate_accepts_hash_only_rejects_embedded_code():
    from corpus.manifest import build_manifest, validate_manifest
    good = build_manifest(carve(fv([ffs(G1, T_DRIVER, b"aaa")])),
                          source={"vendor": "V", "model": "M", "version": "1", "trust_tier": "vendor-signed"})
    ok, issues = validate_manifest(good)
    assert ok, issues
    # someone tries to smuggle firmware bytes into a module entry -> rejected
    bad = json.loads(json.dumps(good))
    bad["modules"][0]["base64"] = "TVqQAAM..." + "A" * 200
    ok2, issues2 = validate_manifest(bad)
    assert not ok2
    assert any("disallowed keys" in i or "embedded data" in i for i in issues2)
    # missing provenance -> rejected
    noprov = json.loads(json.dumps(good))
    noprov["source"].pop("vendor")
    ok3, issues3 = validate_manifest(noprov)
    assert not ok3 and any("vendor" in i for i in issues3)


def test_blob_manifest_for_opaque_chip_firmware():
    from corpus.manifest import build_blob_manifest, match_blob
    fw = b"opaque-ssd-controller-firmware-blob" * 100   # non-UEFI, no FVs
    m = build_blob_manifest(fw, source={"vendor": "ACME", "model": "SSD-X",
                                        "version": "1.2", "trust_tier": "vendor-signed"},
                            component_type="X-Device")
    assert m["kind"] == "blob"
    assert m["source"]["component_type"] == "X-Device"
    assert match_blob(fw, m)["content_verdict"] == "CONTENT-MATCH"
    tampered = fw[:-1] + b"X"
    assert match_blob(tampered, m)["content_verdict"] == "ANOMALOUS"


def test_corroborated_tier_not_clean_capable():
    from corpus.manifest import CLEAN_CAPABLE_TIERS, TRUST_TIERS
    assert "multi-source-corroborated" in TRUST_TIERS
    assert "multi-source-corroborated" not in CLEAN_CAPABLE_TIERS  # N sources may share a bad origin


def test_config_server_resolution():
    import os
    import tempfile
    from corpus import config
    # env override wins
    old = os.environ.get("SPIEYES_SERVER")
    os.environ["SPIEYES_SERVER"] = "http://envwins:1"
    try:
        assert config.server_url() == "http://envwins:1"
    finally:
        os.environ.pop("SPIEYES_SERVER", None)
        if old is not None:
            os.environ["SPIEYES_SERVER"] = old
    # spi-eyes.ini in cwd (simulates the file shipped next to the exe)
    saved_env = os.environ.pop("SPIEYES_SERVER", None)
    cwd = os.getcwd()
    d = tempfile.mkdtemp()
    try:
        with open(os.path.join(d, "spi-eyes.ini"), "w", encoding="utf-8") as fh:
            fh.write("[server]\nurl = http://iniwins:2\n")
        os.chdir(d)
        assert config.server_url() == "http://iniwins:2"
    finally:
        os.chdir(cwd)
        if saved_env is not None:
            os.environ["SPIEYES_SERVER"] = saved_env


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all corpus tests passed")


if __name__ == "__main__":
    _run()
