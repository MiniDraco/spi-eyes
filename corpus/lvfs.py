"""LVFS bulk ingester -- the legitimate 'massive stack'.

The Linux Vendor Firmware Service (fwupd.org) is a public, vendor-SIGNED firmware
repository with a machine-readable catalog. This module enumerates it and mints
Tier-1 (vendor-signed) references at scale -- clean provenance, no grey sources,
no redistribution (images are extracted, hashed, and discarded; only hash-only
manifests are kept).

Pipeline: catalog (firmware.xml.gz) -> per release .cab -> extract (expand.exe on
Windows / cabextract on Linux) -> pick the UEFI payload -> carve -> versioned manifest.

Note: some vendors (e.g. Dell PFS) wrap the payload in a format our carver doesn't
yet unwrap -> those are skipped and reported, not silently dropped.
"""
from __future__ import annotations

import glob
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from .index import DEFAULT_REFS_DIR, norm
from .manifest import build_blob_manifest, build_image_manifest, save_manifest
from .uefifv import carve

CATALOG_URL = "https://cdn.fwupd.org/downloads/firmware.xml.gz"
_UA = {"User-Agent": "fwupd/1.9.0 SPI-Eyes-corpus-ingester"}


def fetch_catalog(timeout: int = 120) -> bytes:
    raw = urllib.request.urlopen(urllib.request.Request(CATALOG_URL, headers=_UA), timeout=timeout).read()
    return gzip.decompress(raw)


def parse_catalog(xml_bytes: bytes, category: Optional[str] = "X-System") -> List[dict]:
    root = ET.fromstring(xml_bytes)
    out: List[dict] = []
    for c in root.findall(".//component"):
        cats = [x.text for x in c.findall("categories/category")]
        if category and category not in cats:
            continue
        model = c.findtext("name") or ""
        vendor = c.findtext("developer_name") or ""
        for rel in c.findall("releases/release"):
            ver = rel.get("version") or rel.findtext("version") or ""
            loc = rel.findtext("location")
            if not loc or not ver:
                continue
            loc = loc.replace("https://fwupd.org/", "https://cdn.fwupd.org/")
            out.append({"vendor": vendor, "model": model, "version": ver,
                        "url": loc, "category": ",".join(c for c in cats if c)})
    return out


_META_EXT = (".cab", ".metainfo.xml", ".jcat", ".inf", ".txt", ".asc", ".sig")


def _extract_firmware(cab_bytes: bytes) -> Optional[bytes]:
    """Extract a .cab and return the firmware payload: the largest non-metadata file.
    Works for UEFI capsules AND opaque chip/device firmware blobs (SSD/TB/NIC/EC)."""
    d = tempfile.mkdtemp()
    try:
        cabp = os.path.join(d, "fw.cab")
        with open(cabp, "wb") as fh:
            fh.write(cab_bytes)
        if shutil.which("expand"):        # Windows built-in
            subprocess.run(["expand", "-F:*", cabp, d], capture_output=True, text=True, timeout=180)
        elif shutil.which("cabextract"):  # Linux/mac
            subprocess.run(["cabextract", "-d", d, cabp], capture_output=True, text=True, timeout=180)
        else:
            return None
        best = None
        for f in glob.glob(os.path.join(d, "**", "*"), recursive=True):
            if not os.path.isfile(f) or f.lower().endswith(_META_EXT) or "readme" in os.path.basename(f).lower():
                continue
            with open(f, "rb") as fh:
                data = fh.read()
            if best is None or len(data) > len(best):
                best = data
        return best
    finally:
        shutil.rmtree(d, ignore_errors=True)


def download(url: str, timeout: int = 180) -> bytes:
    return urllib.request.urlopen(urllib.request.Request(url, headers=_UA), timeout=timeout).read()


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", norm(s)).strip("-") or "x"


def ingest_lvfs(limit: int = 8, max_attempts: int = 20, category: Optional[str] = None,
                tier: str = "vendor-signed", refs_dir: str = DEFAULT_REFS_DIR,
                skip_vendors=("dell",), delay: float = 1.5, on_result=None) -> List[dict]:
    """Ingest up to `limit` successful vendor-signed references from LVFS.

    skip_vendors: vendor name substrings to skip WITHOUT downloading (e.g. Dell uses a
    PFS wrapper our carver can't yet unwrap -- skipping avoids wasted CDN hits).
    delay: seconds between downloads (politeness; the CDN 502s under rapid access).
    """
    import time
    entries = parse_catalog(fetch_catalog(), category)
    os.makedirs(refs_dir, exist_ok=True)
    results: List[dict] = []
    ok_count = attempts = 0
    seen = set()
    for e in entries:
        if ok_count >= limit or attempts >= max_attempts:
            break
        vlow = norm(e["vendor"])
        if any(s in vlow for s in skip_vendors):     # skip w/o downloading
            continue
        key = (vlow, norm(e["model"]), norm(e["version"]))
        if key in seen:
            continue
        seen.add(key)
        attempts += 1
        if attempts > 1 and delay:
            time.sleep(delay)
        r = {"vendor": e["vendor"], "model": e["model"], "version": e["version"],
             "category": e["category"]}
        try:
            payload = _extract_firmware(download(e["url"]))
            if not payload:
                r.update(ok=False, error="no extractable firmware payload")
            else:
                src = {"vendor": e["vendor"], "model": e["model"], "version": e["version"],
                       "trust_tier": tier, "source": "LVFS", "source_url": e["url"],
                       "component_type": e["category"],
                       "image_sha256": hashlib.sha256(payload).hexdigest()}
                cr = carve(payload)
                code = [f for f in cr.all_files if f.is_code]
                if code:                      # UEFI/BIOS -> fine-grained per-module (+ ME/PSP)
                    src["region"] = "UEFI BIOS region + ME/PSP coprocessor"
                    m = build_image_manifest(payload, source=src)
                    kind, nmod = "modules", m["code_module_count"]
                else:                         # opaque chip/device firmware -> whole-image blob
                    m = build_blob_manifest(payload, source=src, component_type=e["category"])
                    kind, nmod = "blob", 0
                fn = f"{_slug(e['vendor'])}_{_slug(e['model'])}_{_slug(e['version'])}.json"
                save_manifest(m, os.path.join(refs_dir, fn))
                r.update(ok=True, kind=kind, code_modules=nmod, file=fn,
                         image_kb=len(payload) // 1024)
                ok_count += 1
        except Exception as ex:  # noqa: BLE001
            r.update(ok=False, error=f"{type(ex).__name__}: {ex}")
        results.append(r)
        if on_result:
            on_result(r)
    return results
