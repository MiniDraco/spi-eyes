"""Reference manifest (the 'cypher') + the line-by-line matcher.

A manifest is the known-good per-module hash list minted from a *trusted* firmware
image (a vendor-signed update, or a coreboot-reproducible build). Matching a target
image against it is the line check: every immutable code module must hash to its
counterpart in the reference; variable data (NVRAM/descriptor/raw) is normalized out.

Trust tiers (per WHITEPAPER §9 / R3) gate what a match is *worth*:
  coreboot-reproducible | vendor-signed  -> a match can support CLEAN (with a
                                            trustworthy read; still blindable otherwise)
  first-seen | consensus                 -> anomaly detection only, NEVER CLEAN
  unverified                             -> test/dev only

A content match is necessary but not sufficient for CLEAN: the read path must also be
trustworthy (external SPI read / DRTM). A match on a blindable software dump stays
CANNOT-VERIFY. This module reports the content diff; the verdict layer applies that rule.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .uefifv import CarveResult, carve

MANIFEST_VERSION = "0.1"
# ordered strongest -> weakest. "multi-source-corroborated" = the same (vendor,model,
# version) image fetched from N independent sources produced identical per-module hashes
# (cross-source agreement, the sourcing analogue of the external-vs-internal read check).
# It is STRONGER than single-source unverified/consensus, but NOT clean-capable on its
# own: N sources can share a common tampered origin. Only an authoritative source
# (coreboot-reproducible / vendor-signed) earns clean-capability.
TRUST_TIERS = ("coreboot-reproducible", "vendor-signed", "multi-source-corroborated",
               "first-seen", "consensus", "unverified")
CLEAN_CAPABLE_TIERS = {"coreboot-reproducible", "vendor-signed"}


def build_manifest(cr: CarveResult, source: Optional[dict] = None,
                   include_data: bool = False) -> dict:
    """Turn a carved reference image into a golden manifest."""
    mods = []
    for f in cr.all_files:
        if f.is_code or include_data:
            mods.append({"guid": f.guid, "type": f.type_name,
                         "sha256": f.body_sha256, "is_code": f.is_code})
    src = dict(source or {})
    tier = src.get("trust_tier", "unverified")
    if tier not in TRUST_TIERS:
        tier = "unverified"
    src["trust_tier"] = tier
    return {
        "spi_eyes_manifest": MANIFEST_VERSION,
        "image_sha256": cr.image_sha256,
        "module_count": len(mods),
        "code_module_count": sum(1 for m in mods if m["is_code"]),
        "source": src,
        "modules": mods,
    }


def save_manifest(m: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2)


def load_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@dataclass
class MatchResult:
    trust_tier: str
    code_total_ref: int
    matched: int = 0
    mismatched: List[dict] = field(default_factory=list)   # guid known, hash differs
    missing: List[dict] = field(default_factory=list)      # in ref, absent from target
    extra: List[dict] = field(default_factory=list)        # in target, not in ref
    all_code_matched: bool = False
    clean_capable_tier: bool = False

    @property
    def anomalies(self) -> int:
        return len(self.mismatched) + len(self.missing) + len(self.extra)

    @property
    def content_verdict(self) -> str:
        # NOTE: content-level only. The verdict layer downgrades to CANNOT-VERIFY when
        # the target image came from a blindable (software) read. Never returns CLEAN here.
        if self.anomalies == 0 and self.all_code_matched:
            return "CONTENT-MATCH"     # -> CLEAN only if read is trustworthy + tier is clean-capable
        return "ANOMALOUS"


def match(target: CarveResult, manifest: dict) -> MatchResult:
    """The line check: compare a target image's code modules against a reference."""
    tier = manifest.get("source", {}).get("trust_tier", "unverified")
    ref_code = [m for m in manifest.get("modules", []) if m.get("is_code")]
    # guid -> set of acceptable hashes (a GUID may legitimately appear more than once)
    ref_by_guid: Dict[str, set] = {}
    for m in ref_code:
        ref_by_guid.setdefault(m["guid"], set()).add(m["sha256"])

    res = MatchResult(trust_tier=tier, code_total_ref=len(ref_code),
                      clean_capable_tier=(tier in CLEAN_CAPABLE_TIERS))

    seen_guids = set()
    for f in target.all_files:
        if not f.is_code:
            continue
        seen_guids.add(f.guid)
        if f.guid not in ref_by_guid:
            res.extra.append({"guid": f.guid, "type": f.type_name, "sha256": f.body_sha256})
        elif f.body_sha256 in ref_by_guid[f.guid]:
            res.matched += 1
        else:
            res.mismatched.append({"guid": f.guid, "type": f.type_name,
                                   "sha256": f.body_sha256,
                                   "expected": sorted(ref_by_guid[f.guid])})
    for guid, hashes in ref_by_guid.items():
        if guid not in seen_guids:
            res.missing.append({"guid": guid, "expected": sorted(hashes)})

    res.all_code_matched = (res.matched == len(ref_code) and res.anomalies == 0)
    return res


def build_from_image(data: bytes, source: Optional[dict] = None) -> dict:
    return build_manifest(carve(data), source=source)
