# Reference manifests — the known-good corpus (hash-only)

Each file here is a **known-good reference manifest**: the per-module SHA-256 hashes
of a firmware image, keyed by module GUID. These are the "cypher" the line-check
matches a target against (`python -m corpus match <image> <reference.json>`).

## Why this is safe to publish (the "submit hashes, not code" model)
A manifest contains **only hashes + GUIDs + metadata — never firmware code.** A
SHA-256 of a work is not the work (this is how NSRL, LVFS, and every AV vendor
publish hashes). So the corpus grows publicly and collaboratively without anyone
hosting a vendor's copyrighted firmware. A user on an un-seen board can run
`corpus build` on their own official update and **submit the resulting hash
manifest** — contributing coverage for the next person, while their firmware image
never leaves their machine.

## Trust tiers (what a match is worth — WHITEPAPER §9 / R3)
- `coreboot-reproducible` — you can independently rebuild the source → highest trust.
- `vendor-signed` — minted from the OEM's official signed update. Clean-capable.
- `first-seen` / `consensus` — community baselines. **Anomaly detection only, never CLEAN.**
- `unverified` — test/dev.

A content match **never earns CLEAN on a blindable (software) read** — only with a
trustworthy read (external SPI / DRTM). The manifest establishes *what should be there*;
the read path establishes *whether you can believe what you measured*.

## Version-exactness (why every version has its own entry)
A machine is matched only against the reference for its **exact** `(vendor, model,
version)`. Module sets differ per BIOS version (e.g. B450M DS3H: F30=458, F50=599,
F60=410, F64=419 code modules) — matching the wrong version would flag every
legitimately-changed module as an implant. If the exact version isn't covered, the
verdict is **CANNOT-VERIFY** (submit that version's manifest), never a cross-version match.

## Ingestion
`python -m corpus ingest <update-url> --vendor V --model M --version X`. For Gigabyte,
direct URLs follow `download.gigabyte.com/FileList/BIOS/mb_bios_<model>_<ver>.zip`
(sometimes an `_n`/`_a` suffix) — enumerable by pattern (crawlers miss them; the site
is JS-rendered). The image is fetched, carved, hashed, and discarded; only this manifest remains.

## Entries
| File | Vendor | Model | Version | Tier | Code modules |
|---|---|---|---|---|---|
| `gigabyte_b450m-ds3h_f30.json` | Gigabyte | B450M DS3H | F30 | vendor-signed | 458 |
| `gigabyte_b450m-ds3h_f50.json` | Gigabyte | B450M DS3H | F50 | vendor-signed | 599 |
| `gigabyte_b450m-ds3h_f60.json` | Gigabyte | B450M DS3H | F60 | vendor-signed | 410 |
| `gigabyte_b450m-ds3h_f64.json` | Gigabyte | B450M DS3H | F64 | vendor-signed | 419 |

*(Minted from official Gigabyte updates; UEFI BIOS region only — AMD PSP + flash
descriptor parsing is a pending unwrapper. Hash-only; contains no firmware code.)*
