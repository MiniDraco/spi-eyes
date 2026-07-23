"""Auto-ingester: firmware update URL -> versioned reference manifest.

Turns a vendor update (the "cypher") into a corpus entry:
  download -> (unzip) -> pick the firmware image -> carve -> mint a versioned,
  hash-only reference at references/<vendor>_<model>_<version>.json.

Only the resulting HASH manifest is kept; the firmware image itself is never
retained or committed (it stays in a temp dir). This is the automation mass_search
feeds: mass_search discovers update URLs at scale, ingest() mints one reference each.
"""
from __future__ import annotations

import io
import os
import re
import urllib.request
import zipfile
from typing import List, Optional, Tuple

from .index import DEFAULT_REFS_DIR, norm
from .manifest import build_image_manifest, save_manifest
from .uefifv import carve

_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SPI-Eyes-corpus-ingester"}
_IMG_EXT = re.compile(r"\.(fd|rom|bin|cap|f\d+[a-z]?|\d{2,3}[a-z]?)$", re.I)


def download(url: str, timeout: int = 90) -> bytes:
    return urllib.request.urlopen(urllib.request.Request(url, headers=_UA), timeout=timeout).read()


def _members(blob: bytes) -> List[Tuple[str, bytes]]:
    """Return (name, bytes) candidates: the raw blob, or files inside a zip."""
    if blob[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(blob))
            return [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]
        except zipfile.BadZipFile:
            pass
    return [("<raw>", blob)]


def pick_firmware_image(blob: bytes) -> Optional[Tuple[str, bytes]]:
    """From a download (zip or raw), choose the member that actually carves to FVs."""
    cands = _members(blob)
    # prefer larger members that look like firmware and contain FV signatures
    cands.sort(key=lambda nb: len(nb[1]), reverse=True)
    best = None
    for name, data in cands:
        if b"_FVH" not in data:
            continue
        r = carve(data)
        if r.ok and r.all_files:
            return (name, data)
        if best is None:
            best = (name, data)
    return best


def ingest(url: str, vendor: str, model: str, version: str,
           tier: str = "vendor-signed", refs_dir: str = DEFAULT_REFS_DIR) -> dict:
    """Download, carve, and write a versioned reference. Returns a small result dict."""
    blob = download(url)
    picked = pick_firmware_image(blob)
    if not picked:
        return {"ok": False, "url": url, "error": "no carveable firmware image found in download"}
    name, data = picked
    cr = carve(data)
    if not cr.ok or not cr.all_files:
        return {"ok": False, "url": url, "error": f"carve failed: {cr.error}"}
    import hashlib
    m = build_image_manifest(data, source={
        "vendor": vendor, "model": model, "version": version, "trust_tier": tier,
        "source_url": url, "image_member": name, "image_sha256": hashlib.sha256(data).hexdigest(),
        "region": "UEFI BIOS region + ME/PSP coprocessor (flash descriptor not parsed)",
    })
    os.makedirs(refs_dir, exist_ok=True)
    fname = f"{_slug(vendor)}_{_slug(model)}_{_slug(version)}.json"
    out = os.path.join(refs_dir, fname)
    save_manifest(m, out)
    return {"ok": True, "url": url, "path": out, "member": name,
            "code_modules": m["code_module_count"], "image_bytes": len(data)}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", norm(s)).strip("-")
