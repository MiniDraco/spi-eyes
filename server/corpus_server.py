"""SPI-Eyes corpus server -- hosts the hash-only reference DB; clients call it.

Run (from repo root):
    uvicorn server.corpus_server:app --host 0.0.0.0 --port 8787
  or
    python -m server.corpus_server

Endpoints:
    GET  /coverage
    GET  /reference?vendor=&model=&version=      -> manifest | 404
    GET  /versions?vendor=&model=
    POST /submit   (body = a manifest JSON)      -> accepted | corroborated | conflict | rejected

Submissions are validated to be well-formed AND hash-only (reuses corpus.manifest.
validate_manifest) before they touch the DB -- no firmware code can enter.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Body, FastAPI, HTTPException  # noqa: E402

from corpus.manifest import validate_manifest  # noqa: E402
from server import db  # noqa: E402

DB_PATH = os.environ.get("SPIEYES_DB", os.path.join(os.path.dirname(__file__), "corpus.db"))
REFS_DIR = os.environ.get("SPIEYES_REFS",
                          os.path.join(os.path.dirname(os.path.dirname(__file__)), "corpus", "references"))

app = FastAPI(title="SPI-Eyes corpus server", version="0.1")
_conn = db.connect(DB_PATH)
_seeded = db.seed_from_dir(_conn, REFS_DIR)


@app.get("/")
def root():
    return {"service": "spi-eyes-corpus", "seeded_from_refs": _seeded, "hash_only": True}


@app.get("/coverage")
def coverage():
    return db.coverage(_conn)


@app.get("/reference")
def reference(vendor: str, model: str, version: str):
    m = db.get(_conn, vendor, model, version)
    if not m:
        raise HTTPException(status_code=404,
                            detail=f"no reference for {vendor} {model} {version} "
                                   f"(have: {db.versions(_conn, vendor, model) or 'none'})")
    return m


@app.get("/versions")
def versions(vendor: str, model: str):
    return {"vendor": vendor, "model": model, "versions": db.versions(_conn, vendor, model)}


@app.post("/submit")
def submit(manifest: dict = Body(...)):
    ok, issues = validate_manifest(manifest)
    if not ok:
        raise HTTPException(status_code=400, detail={"status": "rejected", "issues": issues})
    return db.upsert(_conn, manifest)


def main() -> int:
    import uvicorn
    port = int(os.environ.get("SPIEYES_PORT", "8787"))
    uvicorn.run(app, host=os.environ.get("SPIEYES_HOST", "127.0.0.1"), port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
