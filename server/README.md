# Corpus server — the hash-only reference DB (server side)

Hosts the reference database and serves it to clients. Stores **only manifests** (GUIDs +
hashes + provenance), never firmware code — submissions are validated hash-only before they
touch the DB. Backed by SQLite; seeded from `corpus/references/*.json` on startup.

## Run it (from the repo root)
```bash
pip install fastapi uvicorn
uvicorn server.corpus_server:app --host 0.0.0.0 --port 8787
# or:  python -m server.corpus_server
```
Env: `SPIEYES_DB` (db path), `SPIEYES_REFS` (seed dir), `SPIEYES_HOST`, `SPIEYES_PORT`.

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/coverage` | entries / models / vendors / conflicts + the list |
| GET | `/reference?vendor=&model=&version=` | the reference manifest, or 404 |
| GET | `/versions?vendor=&model=` | versions covered for a model |
| POST | `/submit` (body = a manifest) | accept / corroborate / conflict / reject |

## Submission behaviour (how crowdsourcing hardens the DB)
- **new** `(vendor,model,version)` → **accepted**.
- same version, **identical hashes** → **corroborated** (a counter; independent submitters agreeing).
- same version, **different hashes** → **conflict** — recorded, NOT merged over the stored
  reference. A conflict means a tampered source or a real implant; it's flagged for review.
- fails the hash-only / provenance check → **rejected** (nothing enters the DB).

## The caller side (client)
Zero-dependency (`corpus/client.py`, urllib). Point it at a server with `$SPIEYES_SERVER`
(default `http://127.0.0.1:8787`). It's used automatically by `corpus check` (local-first,
then server) and directly:
```bash
export SPIEYES_SERVER=http://your-server:8787
python -m corpus pull   --vendor Gigabyte --model "B450M DS3H" --version F50
python -m corpus submit  your-reference.json
python -m corpus check   dump.bin --vendor Gigabyte --model "B450M DS3H" --version F50 --read external
```

## Trust note
The server is a *distribution + corroboration* layer, not an authority. A reference is only
as trustworthy as its tier (`vendor-signed` / `coreboot-reproducible` are clean-capable;
`consensus` / `first-seen` are anomaly-only). Corroboration raises confidence; it does not
manufacture authenticity. Conflicts are surfaced, never silently resolved.
