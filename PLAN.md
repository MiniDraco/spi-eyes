# SPI-Eyes — Build Plan (for an Opus session to follow)

This is the execution roadmap. Design rationale lives in [`WHITEPAPER.md`](WHITEPAPER.md)
(v0.2, post Adversarial Pass 1). Read §4–§6, §9, §12, and the Adversarial Pass 1 revisions
(R1–R7) before writing code. This plan is self-contained: an Opus session with no prior
conversation can pick it up.

## Non-negotiable engineering rules (apply to every phase)
1. **Fail closed.** A probe that could be blinded, or that errored, or found no reference,
   returns `CANNOT_VERIFY` / `NOT_ASSESSED` — **never** a CLEAN or a false negative.
2. **Never collapse "couldn't check" into "not present / clean."** (Canonical bug: an
   access-denied TPM query was reported as "TPM not present." Access-denied = `NOT_ASSESSED`.)
3. **Every `Evidence` carries `max_earnable_verdict` + `blindable`.** Aggregation obeys
   `V ≤ max(Mᵢ)`; only hardware-rooted evidence has a ceiling of CLEAN.
4. **Two layers stay separate:** SUSCEPTIBILITY (locks set?) ≠ INFECTION (resident?). A
   susceptibility PASS may never be rendered as "not infected."
5. **Wrap, don't reinvent** (build-engines): CHIPSEC, go-tpm-tools/go-attestation, UEFITool,
   MEAnalyzer, PSPTool, fwhunt-scan, LVFS. New capability = new adapter, not a rewrite.
6. **Read-only by default.** Anything that loads a driver, writes firmware, or touches the
   network is explicit opt-in and clearly logged.

## Current state
- **Phase 1a — Capability Probe: DONE.** `capability_probe/` runs read-only, no driver,
  emits the evidence ceiling + JSON artifact. Verified on the dev box (ceiling =
  CANNOT-VERIFY; no DRTM). Files: `model.py`, `winutil.py`, `probes.py`, `aggregate.py`,
  `__main__.py`.

---

## Phase 1b — Elevate + deepen the no-driver evidence tier
**Goal:** a *complete, honest* susceptibility + capability report on any Windows box, still
with no kernel driver. This is the shippable "everyman" product (WHITEPAPER R6).

Tasks:
- **Self-elevation / manifest.** Detect non-admin (done) and offer a one-click elevated
  re-launch (`Start-Process -Verb RunAs`), or ship a `.cmd` wrapper. Elevated run must
  resolve the TPM / Secure Boot / dbx `NOT-ASSESSED` cases seen on the dev box.
- **TPM depth.** Real TPM 2.0 confirmation, manufacturer (fTPM vs dTPM → interposer-risk
  note), PCR bank availability. Read the TCG event log via TBS (`Tbsi_Get_TCG_Log_Ex`) or
  parse `C:\Windows\Logs\MeasuredBoot\*.log`; report whether an event-log cross-check is
  feasible (do NOT yet claim CLEAN — that's Phase 2).
- **dbx currency, for real.** Bundle a reference list of known-bootkit revocation hashes
  (BlackLotus / CVE-2023-24932, BootHole, Baton Drop) from the UEFI Forum `dbxupdate.bin`.
  Parse the live dbx (parser already in `probes._parse_efi_sig_lists`), and report which
  known-bad hashes are **missing** → ANOMALOUS (susceptibility). Replace the crude
  "count < 40" heuristic.
- **HPA/DCO + drive firmware.** If `smartctl` present, run `smartctl -i` per drive: compare
  `READ NATIVE MAX` vs IDENTIFY capacity → hidden area = ANOMALOUS; pin firmware revision.
  NVMe: firmware slot info via `nvme-cli` or `Get-StorageFirmwareInformation`.
- **Secure Boot key audit.** Enumerate PK/KEK/db/dbx; flag foreign/self-enrolled certs and
  the presence of the revoked Windows Production PCA 2011 without the 2023 CA.
- **Optional ME/PSP version (best-effort, no driver).** Intel `MEInfoWin`/HECI or `Get-CimInstance`
  for ME version → flag downgrade below INTEL-SA-00086 fix. AMD PSP is harder without a driver;
  note as NOT-ASSESSED.

**Acceptance:** elevated run on the dev box returns real TPM + Secure Boot + dbx verdicts;
dbx report names specific missing revocations; HPA/DCO assessed when smartmontools present.
Add `tests/` with a fixture-driven test of `_parse_efi_sig_lists` and the aggregator lattice.

---

## Phase 1c — Driver-load empirical test (answers Q1 on real hardware)
**Goal:** stop *assessing* CHIPSEC loadability and *measure* it. Explicit opt-in, gated.

Tasks:
- On an HVCI-ON and an HVCI-OFF machine, attempt to load the CHIPSEC driver via attestation
  signing (NOT test-signing). Record: loaded? blocked-by-HVCI? blocked-by-vuln-blocklist?
- Measure driver-load **observability**: does load latency / event-log noise create a
  detectable window (informs the "implant quiesces on load" risk, WHITEPAPER open problem #5).
- Output a per-machine "susceptibility layer available: yes/no/degraded" flag that Phase 3
  depends on.

**Acceptance:** a documented yes/no on C5 for ≥3 real machines (mix of Secured-core and
budget). If HVCI universally blocks it, pivot the susceptibility layer to an offline/WinPE
scan mode.

---

## Phase 2 — The earned-CLEAN engine (DRTM quote path)  [needs DRTM-capable hardware]
**Goal:** make `CLEAN (Above-SMM)` real. This is the core research contribution in code.
**Blocker:** the dev box has no DRTM. Need a Secured-core / System-Guard-capable laptop to develop.

**UNBLOCK (built):** `collector/Collect-FirmwareAttestation.ps1` — a standalone, read-only,
zero-network PowerShell capture tool to hand to someone who *has* a Secured-core laptop. It
dumps DeviceGuard/DRTM state + TPM + **raw measured-boot WBCL event logs (base64)** + Secure
Boot vars into two files. That gives real DRTM event-log data to develop the parser +
PCR-reconstruction offline, without a Secured-core box on hand.

**Phase 2 parser: DONE.** `attest/tcglog.py` parses the crypto-agile TCG/WBCL event log
and reconstructs PCR values (the R2 event-log cross-check). Validated against a real 93 KB
WBCL log (36 events, 0 trailing bytes) + deterministic tests in `tests/test_tcglog.py`
(PCR extend math checked vs hashlib). Handles any PCR incl. DRTM 17-22. `python -m attest
<log|collector.json>` decodes + prints. Remaining Phase 2 work below (quote + corpus match).

Tasks:
- Wrap **go-tpm-tools / go-attestation** (Go sidecar invoked from Python, or port the flow):
  obtain a **nonce-bound TPM quote** over the DRTM PCRs (17–22).
- **Mandatory event-log cross-check (R2):** verify the event log reconstructs the quoted
  PCRs AND that each measured component hashes to a known-good corpus entry. Quote without a
  verified log ⇒ CANNOT-VERIFY.
- Emit `CLEAN (Above-SMM)` **only** when quote + log + corpus all agree. Never unconditional
  CLEAN (R1) — record in the verdict that SMM is unmeasured absent an STM + external dump.

**Acceptance:** on a DRTM box, a tampered bootloader flips the verdict from CLEAN(Above-SMM)
to ANOMALOUS; a missing/instrumented event log yields CANNOT-VERIFY.

---

## Phase 3 — Susceptibility engine via CHIPSEC wrap  [gated on Phase 1c / Q1]
Wrap CHIPSEC modules → real register reads: BIOS_CNTL (BLE/SMM_BWP), PRx coverage, FLOCKDN,
D_LCK, SMRR, SMM_Code_Chk_En, Boot Guard SACM_INFO (MSR 0x13A), AMD PSB fuse (MMIO 0x10994).
Map each to SUSCEPTIBILITY verdicts. Remember: these read *susceptibility, not infection*,
and the reads themselves are blindable → INFECTION stays CANNOT-VERIFY.

## Phase 4 — Content / image tier + the external-read primitive
**Carver + matcher: DONE (zero-dep).** `corpus/uefifv.py` carves a UEFI image into per-FFS
modules (GUID + type + SHA-256), descending through **LZMA-compressed volumes** and nested
FVs. `corpus/manifest.py` mints a reference manifest and does the **line check** (per-module
match / mismatch / missing / extra) — catches MoonBounce-style in-place hooks. Validated on a
real 4 MB OVMF image (119 code modules; 1-byte tamper → caught) + `tests/test_corpus.py`.
`python -m corpus build|match`. Remaining: ME/PSP + Dell-PFS/Insyde vendor unwrappers;
Tiano (non-LZMA) decompression; **external-vs-internal diff (C3)** with a benign-divergence
diagnostic tree (needs a live dump — external read / driver).

## Phase 5 — Corpus (CoRIM), tiered + anomaly-only consensus (R3)
**Trust tiers: DONE** (`manifest.py`): coreboot-reproducible / vendor-signed are clean-capable;
first-seen / consensus are **anomaly-only, never CLEAN** (enforced + tested). Remaining: the
**LVFS/vendor-update ingester** (fetch official update → unwrap → mint Tier-1 manifest — "the
cypher is the vendor's own update file"); CoRIM serialization; first-seen baseline store;
population-consensus + canary drift alarm; provenance surfaced in every verdict.

## Phase 6 — Verdict emission + non-suppressibility (R4/R5)
- Sign the verdict as an **EAT (RFC 9711)** nonce-bound token (wrap `veraison/eat`).
- **Out-of-band verifier (R4):** emit the EAT + measurements as a **QR code**; a separate
  phone app verifies the signature + Rekor inclusion proof over its own network and renders
  the true verdict — defeats host-UI spoofing / local packet-drop.
- **Heartbeat logging (R5):** periodic `scan_executed` entries to a transparency log; a
  *missing* heartbeat is the event. Multi-endpoint; network-blocked ⇒ stated as CANNOT-VERIFY.

## Phase 7 — External-read hardware kit (the CLEAN-for-SPI gold tier)
Scripted `flashrom` procedure for **Tigard** (recommended, ~$39) or **Pi Pico + pico-serprog**
(~$35) + genuine SOIC-8 clip. Powered-off, sequential, read-3×-and-hash-for-stability, then
offline diff against the internal dump. Ship clear "power off / isolate / genuine clip" guidance.

---

## Suggested order for the next session
1. **Phase 1b** (highest value, no hardware blockers) — makes the everyman product complete.
2. **Phase 1c** on real machines — answers Q1 empirically; decides Phase 3's feasibility.
3. Acquire a **DRTM-capable laptop**, then **Phase 2** — proves earned-CLEAN exists.
Everything else follows once those three unknowns are nailed to real silicon.
