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

## Sources / ingestion (in trust order)
- **LVFS (bulk, vendor-signed):** `python -m corpus lvfs --limit N` enumerates the
  fwupd.org catalog and mints Tier-1 references. The legitimate "massive stack." Note:
  much LVFS system firmware is Dell-PFS-wrapped or SoC/ARM — those are skipped until the
  matching unwrapper exists; standard AMI/EDK2 capsules (HP, ASRock, Intel NUC…) carve now.
- **Vendor pattern (per model+version):** `python -m corpus ingest <url> ...`. e.g. Gigabyte
  `download.gigabyte.com/FileList/BIOS/mb_bios_<model>_<ver>.zip` (±`_n`/`_a`), enumerable by
  pattern (crawlers miss it — the site is JS-rendered).
- **Cross-source corroboration (grey provenance):** `python -m corpus corroborate <img1>
  <img2> <img3> ...`. Same (vendor,model,version) from ≥2 independent sources; identical
  per-module hashes → `multi-source-corroborated` tier (stronger than single-source, but
  NOT clean-capable — N sources may share a tainted origin). Disagreement = tampered source.

In every path the image is fetched, carved, hashed, and **discarded**; only the hash-only
manifest remains.

## Two reference granularities
- **`modules`** — UEFI/BIOS firmware carved into per-module hashes (localizes tampering,
  MoonBounce-style). Requires a parseable firmware volume.
- **`blob`** — a whole-image hash for opaque **chip/device firmware** we can't carve
  (SSD/NVMe, GPU, Intel ME / AMD PSP, Embedded Controller, Thunderbolt/USB-C, docks).
  Detects ANY change to the image but can't localize it. LVFS carries these too.

## Coverage
Run `python -m corpus list` for the live list. Multi-vendor, multi-component: BIOS
(Gigabyte/HP/ASRock, per-module) **plus chip firmware** — GPU (Intel Arc), Management
Engine (Lenovo), Embedded Controller / USB-C PD (Acer) as blobs. All `vendor-signed`,
all hash-only. Pending unwrappers (Dell PFS, AMD PSP, flash descriptor) will convert some
blobs to per-module. The IRATEMONK-class target (SSD/HDD *controller* content) is largely
version-pin + anomaly only — vendors rarely publish those images.
