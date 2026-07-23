"""Version-aware corpus index.

A machine's firmware must be matched against the reference for its EXACT
(vendor, model, version) -- matching F42 against an F50 reference would flag every
legitimately-changed module as an implant (a false positive). This index maps
(vendor, model, version) -> reference manifest, and returns None (=> CANNOT-VERIFY,
offer to submit) when the exact version is not covered, rather than matching the
wrong version.
"""
from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

DEFAULT_REFS_DIR = os.path.join(os.path.dirname(__file__), "references")


def norm(s: Optional[str]) -> str:
    return " ".join(str(s or "").split()).strip().lower()


def key_of(vendor: str, model: str, version: str) -> Tuple[str, str, str]:
    return (norm(vendor), norm(model), norm(version))


@dataclass
class Entry:
    vendor: str
    model: str
    version: str
    tier: str
    code_modules: int
    path: str
    kind: str = "modules"        # "modules" (UEFI, per-module) or "blob" (opaque chip fw)
    component: str = ""          # LVFS category, e.g. X-Gpu / X-ManagementEngine


class CorpusIndex:
    def __init__(self, refs_dir: str = DEFAULT_REFS_DIR):
        self.refs_dir = refs_dir
        self._by_key: Dict[Tuple[str, str, str], Entry] = {}
        self._load()

    def _load(self) -> None:
        for path in glob.glob(os.path.join(self.refs_dir, "*.json")):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    m = json.load(fh)
                src = m.get("source", {})
                e = Entry(vendor=src.get("vendor", ""), model=src.get("model", ""),
                          version=src.get("version", ""), tier=src.get("trust_tier", "unverified"),
                          code_modules=m.get("code_module_count", 0), path=path,
                          kind=m.get("kind", "modules"), component=src.get("component_type", ""))
                if e.vendor and e.model and e.version:
                    self._by_key[key_of(e.vendor, e.model, e.version)] = e
            except (OSError, json.JSONDecodeError, ValueError):
                continue

    def lookup(self, vendor: str, model: str, version: str) -> Optional[Entry]:
        """Return the reference for the EXACT version, or None (never a near-version)."""
        return self._by_key.get(key_of(vendor, model, version))

    def versions_for(self, vendor: str, model: str) -> List[str]:
        vk, mk = norm(vendor), norm(model)
        return sorted(e.version for (v, m, _), e in self._by_key.items() if v == vk and m == mk)

    def all_entries(self) -> List[Entry]:
        return sorted(self._by_key.values(), key=lambda e: (e.vendor, e.model, e.version))

    def coverage(self) -> Dict[str, int]:
        models = {(e.vendor, e.model) for e in self._by_key.values()}
        return {"entries": len(self._by_key), "models": len(models),
                "vendors": len({e.vendor for e in self._by_key.values()})}
