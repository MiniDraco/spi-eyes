# Contributing firmware references — crowdsource the corpus

SPI-Eyes verifies firmware by matching it against **known-good references**. No public
per-component firmware database exists, so we build one together — **one hash manifest at
a time**. Every contributor covers the boards, versions, and chips they have access to,
and the corpus grows to cover everyone's hardware.

## The one rule: submit HASHES, never firmware code

A reference manifest contains only **GUIDs + SHA-256 hashes + provenance metadata** — never
firmware bytes. A hash is a fingerprint, not the file (the same reason NIST NSRL and LVFS
publish hashes freely). This keeps the corpus legally clean and safe: **firmware images stay
on your machine; only fingerprints travel.** Submissions are auto-checked to enforce this —
anything carrying embedded data is rejected (`corpus validate`).

## How to make a submission

**1. Get the firmware from a trustworthy source** (this determines the trust tier — see below):
- An **official vendor update** (best) — download the BIOS/firmware update for the exact model+version.
- A **coreboot reproducible build** — rebuild from source (highest trust).
- **Donor devices** — read firmware off known-good units (for chips vendors don't publish, e.g. drives).

**2. Mint the manifest** (the image is carved, hashed, and *discarded* — only the JSON remains):
```bash
# from a vendor update URL (auto-download + carve):
python -m corpus ingest <update-url> --vendor "Gigabyte" --model "B450M DS3H" --version F50

# or from a local firmware image you already have:
python -m corpus build <image.fd> --vendor "Gigabyte" --model "B450M DS3H" --version F50 \
    --tier vendor-signed --out gigabyte_b450m-ds3h_f50.json
```

**3. Validate it** (confirms well-formed + hash-only before you share):
```bash
python -m corpus validate gigabyte_b450m-ds3h_f50.json
# -> VALID: ... Safe to submit.
```

**4. Submit** — open a Pull Request adding your `.json` to `corpus/references/`, **or** open an
Issue with the JSON attached. Include in the description **where the firmware came from**
(vendor URL / coreboot build / donor unit / your own machine) and how you obtained it.

## Trust tiers — set `--tier` honestly

| Tier | Use when | Earns CLEAN? |
|---|---|---|
| `coreboot-reproducible` | you rebuilt it from source | yes |
| `vendor-signed` | from the OEM's official signed update | yes |
| `multi-source-corroborated` | same version from ≥2 independent sources, hashes agree | no (may share a bad origin) |
| `first-seen` | earliest measurement seen for a SKU/version | no (anomaly detection) |
| `consensus` | harvested from a running machine / donor | no (anomaly detection) |

**Never label something `vendor-signed` unless it came from the vendor.** A reference built
from *your own running machine* is a `consensus` data point — useful, but it is **not proof of
clean** (your machine could already be compromised). Its value comes from *agreement*: when
many independent submissions of the same version match, confidence rises; an outlier is a
suspect.

## How crowdsourcing hardens the corpus

When multiple people submit the same `(vendor, model, version)`:
- **They agree** → the reference is corroborated across independent submitters (stronger).
- **They disagree** → a loud signal: at least one submitter's firmware differs — possibly a
  real implant, possibly a bad source. Flagged for investigation, not silently merged.

This is the same cross-source-agreement principle SPI-Eyes uses on the metal (external-vs-
internal read), applied to the community. More submitters = more coverage **and** more
confidence.

## Privacy & safety

- A manifest exposes firmware **fingerprints + hardware model/version + provenance** — no
  firmware code, no personal data. Model/version identify the *hardware*, not you.
- Submissions are validated to be **hash-only**; embedded data is rejected automatically.
- If you built from your own machine, that's fine — just tag it `consensus`, and know it
  contributes to anomaly detection, not to an authoritative clean baseline.

## Vendors / PSIRT

If you're a vendor: the lowest-friction contribution is to **publish to
[LVFS](https://fwupd.org/)** (we ingest it automatically) or hand us a **signed RIM / hash
manifest** — you give fingerprints, not code, and never sign an NDA over shipping us images.
Run `corpus build` on your own release and send the JSON; that's the whole ask.
