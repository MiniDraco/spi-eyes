"""Decode a TCG/WBCL event log and print events + reconstructed PCRs.

  python -m attest <path-to-*.log>            # a raw WBCL/TCG event log
  python -m attest <collector-*.json>         # a FirmwareAttest collector artifact
"""
from __future__ import annotations

import base64
import json
import sys

from .tcglog import parse


def _load(path: str) -> bytes:
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        logs = doc.get("measured_boot_logs") or []
        if not logs:
            raise SystemExit("no measured_boot_logs[] in collector JSON")
        b64 = logs[0].get("base64")
        if not b64:
            raise SystemExit("first measured_boot_log has no base64 payload")
        return base64.b64decode(b64)
    with open(path, "rb") as fh:
        return fh.read()


def main(argv) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    data = _load(argv[0])
    r = parse(data)
    print(f"parsed: ok={r.ok}  bytes={len(data)}  events={len(r.events)}  "
          f"algorithms={r.algorithms}  trailing={r.trailing_bytes}")
    if r.error:
        print(f"note: {r.error}")
    if not r.ok:
        return 1

    print("\n-- events --")
    for e in r.events:
        d = e.digests.get("sha256", "")[:16]
        print(f"  #{e.index:<3} PCR{e.pcr:<2} {e.event_type_name:<34} "
              f"{'(no-extend) ' if not e.measured else ''}sha256={d}.. {e.event_summary}")

    print("\n-- reconstructed PCRs (sha256) --")
    sha = r.pcrs.get("sha256", {})
    for pcr in sorted(sha):
        print(f"  PCR{pcr:<2} = {sha[pcr]}")
    print(f"\n{len(sha)} PCR(s) extended. (DRTM PCRs 17-22 appear only on Secure-Launch machines.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
