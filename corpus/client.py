"""Corpus client -- the caller side. Zero-dependency (urllib) so the scanner stays light.

Talks to a corpus server (default http://127.0.0.1:8787, override with $SPIEYES_SERVER)
to look up references it doesn't have locally and to submit new hash-only manifests.
Local-first: callers should check the on-disk corpus, then fall back to the server.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional


def base() -> str:
    return os.environ.get("SPIEYES_SERVER", "http://127.0.0.1:8787").rstrip("/")


def _get(path: str, params: Optional[dict] = None, timeout: int = 10):
    url = base() + path + ("?" + urllib.parse.urlencode(params) if params else "")
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def available() -> bool:
    try:
        _get("/coverage", timeout=4)
        return True
    except Exception:  # noqa: BLE001
        return False


def lookup(vendor: str, model: str, version: str) -> Optional[dict]:
    """Return the reference manifest for an exact version, or None (404 / unreachable)."""
    try:
        return _get("/reference", {"vendor": vendor, "model": model, "version": version})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception:  # noqa: BLE001  (server down -> treat as not covered)
        return None


def versions(vendor: str, model: str) -> List[str]:
    try:
        return _get("/versions", {"vendor": vendor, "model": model}).get("versions", [])
    except Exception:  # noqa: BLE001
        return []


def coverage() -> Optional[dict]:
    try:
        return _get("/coverage")
    except Exception:  # noqa: BLE001
        return None


def submit(manifest: dict, timeout: int = 20) -> dict:
    data = json.dumps(manifest).encode()
    req = urllib.request.Request(base() + "/submit", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode()).get("detail", {"status": "rejected"})
        except Exception:  # noqa: BLE001
            return {"status": "rejected", "reason": f"HTTP {e.code}"}
