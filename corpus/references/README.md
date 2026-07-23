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

## Entries
| File | Vendor | Model | Version | Tier | Code modules |
|---|---|---|---|---|---|
| `gigabyte_b450m-ds3h_f50.json` | Gigabyte | B450M DS3H | F50 | vendor-signed | 599 |

*(Minted from the official Gigabyte update; UEFI BIOS region only — AMD PSP + flash
descriptor parsing is a pending unwrapper. Hash-only; contains no firmware code.)*
