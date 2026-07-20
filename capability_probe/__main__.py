"""SPI-Eyes Capability Probe  ->  `python -m capability_probe`

READ-ONLY. Loads no kernel driver, writes nothing to firmware. Answers, for THIS
machine: what is the best verdict SPI-Eyes could ever earn here? (WHITEPAPER §12)
"""
from __future__ import annotations

import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone

from .aggregate import compute_ceiling
from .model import Layer, Verdict
from .probes import run_all, sku_label
from .winutil import is_admin

_C = {
    Verdict.CLEAN: "\033[92m", Verdict.CLEAN_ABOVE_SMM: "\033[92m",
    Verdict.ANOMALOUS: "\033[93m", Verdict.CANNOT_VERIFY: "\033[90m",
    Verdict.NOT_ASSESSED: "\033[90m",
}
_RST = "\033[0m"


def _tag(v: Verdict) -> str:
    if not sys.stdout.isatty():
        return f"[{v.value}]"
    return f"{_C.get(v,'')}[{v.value}]{_RST}"


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    if platform.system() != "Windows":
        print("SPI-Eyes capability probe targets Windows. Detected:", platform.system())
        # keep running for structure validation, but most probes will no-op.

    host = socket.gethostname()
    admin = is_admin()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("=" * 78)
    print(f" SPI-Eyes  ::  Capability Probe   (read-only, no kernel driver)")
    print(f" host={host}   sku={sku_label()}   utc={ts}   elevated={'YES' if admin else 'NO'}")
    print("=" * 78)
    if not admin:
        print("  NOTE: not elevated. TPM / Secure Boot / dbx require Administrator;")
        print("        those probes will report NOT-ASSESSED. Re-run from an elevated")
        print("        shell for the full susceptibility picture.")

    evs = run_all()
    ceiling = compute_ceiling(evs)

    # ---- headline -------------------------------------------------------------
    print("\n  EVIDENCE CEILING (best verdict this machine can ever earn):")
    print(f"    {_tag(ceiling.verdict)}  {ceiling.verdict.value}")
    print(f"    scope: {ceiling.scope}")

    # ---- by layer -------------------------------------------------------------
    for layer, title in [
        (Layer.CAPABILITY, "CAPABILITY  (what can be proven?)"),
        (Layer.SUSCEPTIBILITY, "SUSCEPTIBILITY  (are the locks set? — exposure, not infection)"),
        (Layer.INFECTION, "INFECTION  (is something resident? — content evidence)"),
    ]:
        rows = [e for e in evs if e.layer == layer]
        if not rows:
            continue
        print(f"\n  {title}")
        for e in rows:
            print(f"    {_tag(e.verdict):>26}  {e.finding}")
            if e.error:
                print(f"        - note: {e.error}")

    # ---- exposure + escalation ------------------------------------------------
    if ceiling.susceptibility_flags:
        print("\n  !  EXPOSURE FLAGS:")
        for f in ceiling.susceptibility_flags:
            print(f"    - {f}")
    if ceiling.escalations:
        print("\n  ^  ESCALATION PATHS (raise the ceiling):")
        for f in ceiling.escalations:
            print(f"    - {f}")

    # ---- honesty caveat -------------------------------------------------------
    print("\n  " + "-" * 74)
    print("  Every probe above is OS-mediated and therefore SPOOFABLE by a resident")
    print("  ring -2/-3 implant. This report states your evidence CEILING, not a")
    print("  clean bill. Nothing here can earn CLEAN — that needs a DRTM quote or an")
    print("  external SPI read (WHITEPAPER §5). Blindable probes fail closed.")

    # ---- artifact -------------------------------------------------------------
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "out")
    os.makedirs(out_dir, exist_ok=True)
    artifact = {
        "tool": "spi-eyes/capability_probe", "version": "0.2",
        "host": host, "sku": sku_label(), "utc": ts, "elevated": admin,
        "ceiling": {
            "verdict": ceiling.verdict.value, "scope": ceiling.scope,
            "clean_reachable": ceiling.clean_reachable,
            "drtm_running": ceiling.drtm_running, "tpm20": ceiling.tpm20,
            "hvci_running": ceiling.hvci_running,
            "exposure_flags": ceiling.susceptibility_flags,
            "escalations": ceiling.escalations,
        },
        "evidence": [e.to_json() for e in evs],
    }
    path = os.path.join(out_dir, f"capability-{host}-{ts.replace(':','').replace('-','')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2)
    print(f"\n  artifact: {path}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
