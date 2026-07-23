"""Cross-source corroboration for grey-provenance firmware.

The idea (user's): you cannot trust any single grey source, but if you obtain the
SAME (vendor, model, version) image from N INDEPENDENT sources and they produce
IDENTICAL per-module hashes, an attacker would have had to compromise every source
identically. This is the sourcing analogue of the external-vs-internal read check
("verify the same way we do on the metal").

Honest bound: agreement proves *consistency*, not *authenticity* -- N sources can
share a common tampered origin (they all copied the same bad upload). So a corroborated
manifest lands in the `multi-source-corroborated` tier: stronger than single-source, but
NOT clean-capable unless one of the sources is authoritative (vendor-signed / coreboot).
Disagreement is a loud signal: at least one source is tampered/corrupt -> do not ingest.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .manifest import build_manifest
from .uefifv import carve


@dataclass
class Corroboration:
    sources: List[str]
    agree: bool
    module_count: int
    disagreements: List[dict] = field(default_factory=list)  # guid -> per-source hashes
    manifest: Optional[dict] = None
    error: Optional[str] = None


def _code_map(data: bytes):
    """Return (guid -> sorted tuple of code-module hashes, CarveResult)."""
    cr = carve(data)
    d: Dict[str, set] = {}
    for f in cr.all_files:
        if f.is_code:
            d.setdefault(f.guid, set()).add(f.body_sha256)
    return {g: tuple(sorted(h)) for g, h in d.items()}, cr


def corroborate(sources: List[Tuple[str, bytes]], vendor: str, model: str,
                version: str) -> Corroboration:
    """sources: list of (source_label, image_bytes). Needs >= 2 (>= 3 recommended)."""
    if len(sources) < 2:
        return Corroboration(sources=[s for s, _ in sources], agree=False, module_count=0,
                             error="need at least 2 independent sources (3+ recommended)")
    maps: List[Tuple[str, Dict[str, Tuple[str, ...]]]] = []
    carves = []
    for label, data in sources:
        m, cr = _code_map(data)
        maps.append((label, m))
        carves.append(cr)

    all_guids = set().union(*[set(m.keys()) for _, m in maps])
    disagreements = []
    for g in sorted(all_guids):
        per_source = {label: list(m.get(g, ())) for label, m in maps}
        distinct = {tuple(v) for v in per_source.values()}
        if len(distinct) > 1:                      # some source differs (or is missing it)
            disagreements.append({"guid": g, "per_source": per_source})

    agree = not disagreements
    manifest = None
    if agree:
        manifest = build_manifest(carves[0], source={
            "vendor": vendor, "model": model, "version": version,
            "trust_tier": "multi-source-corroborated",
            "corroborated_by": len(sources), "sources": [s for s, _ in sources]})
    return Corroboration(sources=[s for s, _ in sources], agree=agree,
                         module_count=len(all_guids), disagreements=disagreements,
                         manifest=manifest)
