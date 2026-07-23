"""SQLite store for the corpus server -- the hash-only reference database.

Holds only manifests (GUIDs + hashes + provenance), never firmware code. Submissions
of the same (vendor, model, version) that AGREE increment a corroboration count; ones
that DISAGREE are recorded as conflicts (a tampered source or a real implant), never
silently merged over the stored reference.
"""
from __future__ import annotations

import glob
import json
import os
import sqlite3
import time
from typing import List, Optional


def _key(v: str, m: str, ver: str):
    return v.strip().lower(), m.strip().lower(), ver.strip().lower()


def connect(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS refs(
            vendor TEXT, model TEXT, version TEXT, tier TEXT, kind TEXT,
            code_modules INTEGER, corroborations INTEGER DEFAULT 1,
            first_seen REAL, manifest TEXT,
            PRIMARY KEY(vendor, model, version));
        CREATE TABLE IF NOT EXISTS conflicts(
            vendor TEXT, model TEXT, version TEXT, seen REAL, note TEXT, manifest TEXT);
    """)
    return conn


def _module_sig(m: dict):
    """Identity of a manifest for agreement: sorted code (guid,hash) + kind + blob hash."""
    mods = sorted((x.get("guid"), x.get("sha256")) for x in m.get("modules", []) if x.get("is_code"))
    return (m.get("kind", "modules"), m.get("image_sha256"), tuple(mods))


def load(conn: sqlite3.Connection, manifest: dict) -> None:
    """Seed a reference without corroboration logic (INSERT OR IGNORE -> never clobbers
    DB state built from submissions)."""
    src = manifest.get("source", {})
    v, m, ver = src.get("vendor"), src.get("model"), src.get("version")
    if not (v and m and ver):
        return
    vk, mk, vek = _key(v, m, ver)
    conn.execute(
        "INSERT OR IGNORE INTO refs(vendor,model,version,tier,kind,code_modules,corroborations,first_seen,manifest)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (vk, mk, vek, src.get("trust_tier", "unverified"), manifest.get("kind", "modules"),
         manifest.get("code_module_count", 0), max(1, int(src.get("corroborated_by", 1))),
         time.time(), json.dumps(manifest)))
    conn.commit()


def seed_from_dir(conn: sqlite3.Connection, refs_dir: str) -> int:
    n = 0
    for path in glob.glob(os.path.join(refs_dir, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                load(conn, json.load(fh))
            n += 1
        except (OSError, json.JSONDecodeError):
            continue
    return n


def upsert(conn: sqlite3.Connection, manifest: dict) -> dict:
    """Handle a submission: new -> accept; same-as-stored -> corroborate; differs -> conflict."""
    src = manifest.get("source", {})
    v, m, ver = src.get("vendor"), src.get("model"), src.get("version")
    if not (v and m and ver):
        return {"status": "rejected", "reason": "missing provenance (vendor/model/version)"}
    vk, mk, vek = _key(v, m, ver)
    row = conn.execute("SELECT manifest,corroborations FROM refs WHERE vendor=? AND model=? AND version=?",
                       (vk, mk, vek)).fetchone()
    if row is None:
        load(conn, manifest)
        return {"status": "accepted", "new": True, "vendor": v, "model": m, "version": ver}
    if _module_sig(json.loads(row[0])) == _module_sig(manifest):
        conn.execute("UPDATE refs SET corroborations=corroborations+1 WHERE vendor=? AND model=? AND version=?",
                     (vk, mk, vek))
        conn.commit()
        return {"status": "corroborated", "corroborations": row[1] + 1}
    conn.execute("INSERT INTO conflicts VALUES(?,?,?,?,?,?)",
                 (vk, mk, vek, time.time(), "hashes differ from stored reference", json.dumps(manifest)))
    conn.commit()
    return {"status": "conflict",
            "reason": "submitted hashes differ from the stored reference for this exact version — "
                      "a tampered source or a real implant. Recorded for review, NOT merged."}


def get(conn: sqlite3.Connection, v: str, m: str, ver: str) -> Optional[dict]:
    vk, mk, vek = _key(v, m, ver)
    row = conn.execute("SELECT manifest,corroborations FROM refs WHERE vendor=? AND model=? AND version=?",
                       (vk, mk, vek)).fetchone()
    if not row:
        return None
    man = json.loads(row[0])
    man["_corroborations"] = row[1]
    return man


def versions(conn: sqlite3.Connection, v: str, m: str) -> List[str]:
    vk, mk, _ = _key(v, m, "")
    return [r[0] for r in conn.execute(
        "SELECT version FROM refs WHERE vendor=? AND model=? ORDER BY version", (vk, mk)).fetchall()]


def coverage(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT vendor,model,version,tier,code_modules,corroborations FROM refs "
                        "ORDER BY vendor,model,version").fetchall()
    vendors = len({r[0] for r in rows})
    models = len({(r[0], r[1]) for r in rows})
    conflicts = conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0]
    return {"entries": len(rows), "models": models, "vendors": vendors, "conflicts": conflicts,
            "list": [{"vendor": r[0], "model": r[1], "version": r[2], "tier": r[3],
                      "code_modules": r[4], "corroborations": r[5]} for r in rows]}
