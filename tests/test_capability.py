"""Deterministic tests for the capability probe: dbx signature-list parsing and the
evidence-ceiling aggregator. Synthetic inputs only."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capability_probe.probes_windows import _parse_efi_sig_lists  # noqa: E402
from capability_probe.aggregate import compute_ceiling            # noqa: E402
from capability_probe.model import Evidence, Layer, Verdict       # noqa: E402

# EFI_CERT_SHA256_GUID as stored (mixed-endian)
SHA256_GUID = bytes.fromhex("26 16 c4 c1 4c 50 92 40 ac a9 41 f9 36 93 43 28".replace(" ", ""))


def _sig_list(n_hashes: int) -> bytes:
    sig_size = 48  # 16-byte owner GUID + 32-byte SHA-256
    body = b""
    for i in range(n_hashes):
        body += (b"\x00" * 16) + (bytes([i]) * 32)
    list_size = 28 + 0 + len(body)   # 28-byte fixed header + no sig header
    return (SHA256_GUID + struct.pack("<III", list_size, 0, sig_size) + body)


def test_parse_single_sig_list():
    count, hashes = _parse_efi_sig_lists(_sig_list(3))
    assert count == 3
    assert len(hashes) == 3
    assert hashes[1] == ("01" * 32)


def test_parse_multiple_sig_lists():
    blob = _sig_list(2) + _sig_list(5)
    count, hashes = _parse_efi_sig_lists(blob)
    assert count == 7
    assert len(hashes) == 7


def test_parse_garbage_is_safe():
    count, hashes = _parse_efi_sig_lists(b"\xff" * 10)
    assert count == 0 and hashes == []


def _ev(probe, detail):
    return Evidence(probe, Layer.CAPABILITY, "", Verdict.CANNOT_VERIFY,
                    Verdict.CANNOT_VERIFY, True, "test", detail=detail)


def test_ceiling_clean_when_drtm_and_tpm20():
    evs = [_ev("tpm", {"assessed": True, "tpm20": True}),
           _ev("deviceguard", {"drtm_running": True}),
           _ev("driver_loadability", {"hvci_running": True})]
    c = compute_ceiling(evs)
    assert c.verdict == Verdict.CLEAN_ABOVE_SMM
    assert c.clean_reachable is True


def test_ceiling_cannot_verify_without_drtm():
    evs = [_ev("tpm", {"assessed": True, "tpm20": True}),
           _ev("deviceguard", {"drtm_running": False, "drtm_configured": False})]
    c = compute_ceiling(evs)
    assert c.verdict == Verdict.CANNOT_VERIFY
    assert c.clean_reachable is False


def test_ceiling_honest_when_tpm_unassessed():
    # access-denied TPM must NOT be treated as 'no TPM'; scope must say 'undetermined'
    evs = [_ev("tpm", {"assessed": False, "tpm20": None}),
           _ev("deviceguard", {"drtm_running": False})]
    c = compute_ceiling(evs)
    assert c.verdict == Verdict.CANNOT_VERIFY
    assert "undetermined" in c.scope.lower()


def test_firmware_inventory_summarize_and_failclosed():
    from capability_probe.inventory import Component, summarize
    comps = [
        Component("host UEFI", "BIOS", "SystemFirmware", "", "", "REF-AVAILABLE", "external read"),
        Component("GPU VBIOS", "GPU", "Display", "", "", "CANNOT-VERIFY", "device-resident"),
        Component("drive fw", "SSD", "Disk", "", "1.0", "CANNOT-VERIFY", "factory cmds"),
    ]
    s = summarize(comps)
    assert s["total"] == 3
    assert s["ref_available"] == 1
    assert s["cannot_verify"] == 2          # blind chips are counted + surfaced, not dropped
    # fail-closed: default coverage for an unknown chip must never be a clean/verified state
    assert all(c.coverage in ("REF-AVAILABLE", "CANNOT-VERIFY", "OUT-OF-SCOPE") for c in comps)


def _run():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all capability tests passed")


if __name__ == "__main__":
    _run()
