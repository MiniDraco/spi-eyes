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
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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
        "kind": "modules",
        "image_sha256": cr.image_sha256,
        "module_count": len(mods),
        "code_module_count": sum(1 for m in mods if m["is_code"]),
        "source": src,
        "modules": mods,
    }


def build_blob_manifest(data: bytes, source: Optional[dict] = None,
                        component_type: Optional[str] = None) -> dict:
    """Whole-image reference for chip/device firmware we can't carve into modules
    (SSD/NVMe/Thunderbolt/NIC/EC/ME/PSP blobs). Coarser than per-module: it detects
    ANY change to the firmware image but cannot localize which byte changed."""
    src = dict(source or {})
    tier = src.get("trust_tier", "unverified")
    src["trust_tier"] = tier if tier in TRUST_TIERS else "unverified"
    if component_type:
        src["component_type"] = component_type
    return {
        "spi_eyes_manifest": MANIFEST_VERSION, "kind": "blob",
        "image_sha256": hashlib.sha256(data).hexdigest(), "image_size": len(data),
        "module_count": 0, "code_module_count": 0, "source": src, "modules": [],
    }


def match_blob(data: bytes, manifest: dict) -> dict:
    """Whole-image match for a blob reference."""
    got = hashlib.sha256(data).hexdigest()
    exp = manifest.get("image_sha256")
    return {"match": got == exp, "expected": exp, "got": got,
            "content_verdict": "CONTENT-MATCH" if got == exp else "ANOMALOUS"}


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_MODULE_KEYS = {"guid", "type", "sha256", "is_code"}


def validate_manifest(m: dict) -> Tuple[bool, List[str]]:
    """Gate for crowdsourced submissions: confirm a manifest is well-formed AND
    HASH-ONLY (no firmware code can ride in). Rejects disallowed module keys,
    non-hex hashes, and suspiciously long strings (possible embedded data)."""
    issues: List[str] = []
    if m.get("spi_eyes_manifest") != MANIFEST_VERSION:
        issues.append(f"spi_eyes_manifest must be {MANIFEST_VERSION!r}")
    src = m.get("source") or {}
    for k in ("vendor", "model", "version"):
        if not src.get(k):
            issues.append(f"source.{k} is required (provenance)")
    if src.get("trust_tier") not in TRUST_TIERS:
        issues.append(f"source.trust_tier must be one of {TRUST_TIERS}")

    kind = m.get("kind", "modules")
    if kind == "blob":
        if not _HEX64.match(str(m.get("image_sha256", ""))):
            issues.append("blob: image_sha256 must be 64 hex chars")
    else:
        mods = m.get("modules")
        if not isinstance(mods, list):
            issues.append("modules must be a list")
        else:
            for i, mod in enumerate(mods):
                if not isinstance(mod, dict):
                    issues.append(f"module[{i}] must be an object")
                    continue
                extra = set(mod) - _ALLOWED_MODULE_KEYS
                if extra:
                    issues.append(f"module[{i}] has disallowed keys {sorted(extra)} "
                                  f"(HASH-ONLY: {sorted(_ALLOWED_MODULE_KEYS)})")
                if not _HEX64.match(str(mod.get("sha256", ""))):
                    issues.append(f"module[{i}].sha256 must be 64 hex chars")
                for k, v in mod.items():
                    if isinstance(v, str) and len(v) > 128:
                        issues.append(f"module[{i}].{k} is suspiciously long "
                                      f"(possible embedded data — submissions are hash-only)")
    return (len(issues) == 0, issues)


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


def build_image_manifest(data: bytes, source: Optional[dict] = None) -> dict:
    """Full manifest for a firmware image: UEFI per-module hashes PLUS the coprocessor
    (Intel ME / AMD PSP) per-entry hashes carved from the same SPI image."""
    from .coproc import parse as parse_coproc
    m = build_manifest(carve(data), source=source)
    co = parse_coproc(data)
    added = 0
    for e in co.entries:
        if e.sha256:
            m["modules"].append({
                "guid": f"{e.kind.lower()}:{e.name}:{e.offset:08x}",
                "type": f"coproc/{e.kind}", "sha256": e.sha256, "is_code": True})
            added += 1
    if added:
        m["module_count"] = len(m["modules"])
        m["code_module_count"] = sum(1 for x in m["modules"] if x.get("is_code"))
        m["source"]["coproc"] = co.kind
        m["source"]["coproc_entries"] = added
    return m


def build_from_image(data: bytes, source: Optional[dict] = None) -> dict:
    return build_image_manifest(data, source=source)
