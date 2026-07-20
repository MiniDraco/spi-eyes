# SPI-Eyes — White Paper

**A vendor-neutral, fail-closed, off-host firmware-integrity verifier for commodity Windows PCs.**
*A software realization of the NIST SP 800-193 "Detect" pillar for the machines the silicon root-of-trust never reached.*

- **Status:** Design theory, pre-implementation. Intended for adversarial review.
- **Version:** 0.2 (2026-07-20) — incorporates Adversarial Pass 1 (Gemini, ChatGPT, Grok, GitHub Copilot). See "Adversarial Pass 1" section below.
- **Reviewer instruction:** This document is written to be attacked. §14 enumerates every load-bearing claim with a confidence level. If you are an adversarial reviewer, start there and try to break them. Do not be polite. A confirmed refutation of any C-claim marked *high-impact* changes the architecture.

---

## Abstract

Firmware antivirus is the hardest instance of the antivirus problem. Classic AV assumes the OS beneath it is honest; a firmware verifier cannot, because the thing it inspects (SPI flash, SMM, Intel ME / AMD PSP, option ROMs, drive-controller firmware) sits *beneath* the software doing the inspecting. This produces a root-of-trust circularity: **you cannot establish trust about a system's lowest layer using tools that run on top of that layer.** No purely-software, on-host tool can therefore be *guaranteed* sound against an adversary resident at ring -2 (SMM) or ring -3 (ME/PSP).

We do not attempt to defeat that theorem. We invert the goal. SPI-Eyes never claims a machine is "clean" unless clean was *earned* by hardware-rooted evidence the resident adversary cannot forge. Its only legal verdicts are **CLEAN** (earned), **ANOMALOUS**, and **CANNOT-VERIFY**. Any probe that could have been blinded by a resident implant fails **closed** to CANNOT-VERIFY — never to CLEAN. The adversary's best achievable outcome is to convert a CLEAN into a CANNOT-VERIFY; they can never convert an infection into a false all-clear. In this framing, an implant's own act of hiding trips the wire.

The design is an *orchestrator*: it wraps mature, maintained tools (CHIPSEC, go-attestation/go-tpm-tools, UEFITool, MEAnalyzer, PSPTool, fwhunt-scan, LVFS) behind a single fail-closed verdict lattice, emits its verdict as a signed, nonce-bound EAT (RFC 9711) token, and logs verdict hashes to a transparency log so a bad verdict cannot be silently suppressed. Its novelty is not any single probe; it is the verdict semantics, the Windows-consumer orchestration, and the discipline of treating the scanner's own blindability as the primary threat.

---

## Adversarial Pass 1 — Results & Revisions (v0.2)

Four independent engines (Gemini, ChatGPT, Grok, GitHub Copilot) reviewed v0.1 against the §14 claims ledger. **No new fatal hole was found; every serious objection landed on a claim already flagged high-risk (C1/SMM, C2, C6, C7, C10).** The core invariant and evidence lattice were independently judged the genuine contribution (*"that is actually an architecture"*; originality 9/10). **C3** (external-vs-internal divergence) and **C4** (timing attestation is dead on modern x86) survived with no counterexample. The following revisions are adopted; each is re-exposed as a target for Pass 2.

**R1 — `CLEAN (Above-SMM)` becomes a structural verdict type (fixes C1/SMM).** DRTM does not re-measure SMM (absent an STM, ~never present on consumer hardware), so a DRTM quote may verify while a ring-2 implant retains control. A DRTM quote may therefore **never** yield an *unconditional* CLEAN. The verdict is renamed `CLEAN (Above-SMM)`, and the EAT token records that SMM state is unmeasured unless SMRR / D_LCK / SMM_Code_Chk_En are validated **and** corroborated by a clean external SPI dump — only then may scope widen toward unconditional CLEAN.

**R2 — DRTM quote alone is insufficient; event-log cross-check is mandatory (hardens C1).** Elevated from the red→green appendix to a core rule: a quote must ship with an event log that (a) reconstructs the quoted PCRs and (b) whose measured components independently hash to known-good. Quote-without-verified-log ⇒ CANNOT-VERIFY.

**R3 — Population consensus is demoted to anomaly-only; it may NEVER produce CLEAN (fixes C7).** A supply-chain/interdiction implant infecting the majority of a SKU would otherwise become "consensus clean." Consensus now only *detects weirdness*; a consensus-only match ⇒ CANNOT-VERIFY (with "matches N% of SKU" as context), never CLEAN. Adds a first-seen historical baseline tier and a canary set of known-good images monitored for consensus drift/contamination. (See revised §9.)

**R4 — Out-of-band verifier makes the off-host verdict real for a lone consumer (fixes C10).** A self-emitted EAT rendered by a process on the compromised host is theater — ring 0/-2 can patch the UI or drop the packet. Fix: SPI-Eyes emits the signed EAT + measurements as a **QR code** (or file); the user verifies it on a **separate, uncompromised device** (phone app) that checks the COSE signature and the Rekor inclusion proof over *its own* network and renders the true verdict. This moves both rendering and network egress off the suspect host — the minimal architecture that makes "off-host" non-fictional without an enterprise server.

**R5 — Heartbeat logging closes the silent-suppression gap (fixes C6).** Rekor proves only "an upload succeeded," not "nothing was blocked." SPI-Eyes emits a scheduled `scan_executed` heartbeat even when clean; a **missing** heartbeat is itself the event. Log to multiple independent endpoints; a machine whose network the adversary controls is treated as CANNOT-VERIFY for suppression purposes, stated honestly.

**R6 — Reposition: the primary consumer product is the Evidence-Ceiling / Posture Analyzer, not a CLEAN oracle (addresses C2).** C2 is the live existential risk: DRTM/System Guard is absent on most commodity consumer PCs, so earned CLEAN is unreachable for the majority and the honest output is CANNOT-VERIFY. Rather than let that read as "useless," the headline deliverable becomes the **Capability Probe's evidence ceiling + susceptibility + anomaly report** ("this PC lacks DRTM; max earnable trust = CANNOT-VERIFY; here are your exposed SPI locks / stale dbx / enabled DCI / unpatched SA-class exposure"). Earned CLEAN is the escalation tier for DRTM-capable machines or external-read users. Framing/scope pivot, not a patch — it makes the tool useful on day one for the machines that can never say CLEAN.

**R7 — Reframe the contribution around evidence-bounded verdicts, not "antivirus."** Reviewer consensus: the novelty is the fail-closed evidence-classification lattice, not another firmware scanner. Working research title: *"Fail-Closed Firmware Integrity Verification Using Evidence-Bounded Verdicts."* Compare to RATS / Keylime / Dell SafeBIOS, not Norton.

**Formalization of the invariant (adopted).** For evidence items `Eᵢ` with trust class `Tᵢ` and per-item maximum verdict `Mᵢ`, the aggregate verdict `V` satisfies:

> **V ≤ max(Mᵢ)**, where `Mᵢ = CLEAN(scope)` **iff** `Eᵢ` originates from a hardware-rooted measurement whose covered domain includes `scope` (and, for DRTM, `scope` excludes SMM per R1); **otherwise `Mᵢ ≤ CANNOT-VERIFY`.**

This makes C1 a statement reviewers can reason over: no evidence item may raise the verdict above its trust ceiling, and only hardware-rooted evidence has a ceiling of CLEAN.

**Unchanged / validated:** **C3** — sound, but add a benign-divergence diagnostic tree (rule out descriptor read-locks, flash shadowing, and bus contention before flagging infection). **C4** — no modern timing-attestation counterexample surfaced. **C8** — wrap targets confirmed. The **Capability Probe first** (§12) was independently recommended by all four reviewers as the correct first milestone.

---

## 1. Problem Statement

### 1.1 Why firmware AV is the hard case
Detection of malicious code is undecidable in the general case (Rice's theorem). Classic AV sidesteps this with signatures (recognizing known-bad) and heuristics (behavior that looks bad), both of which assume a trusted substrate — the OS — from which to observe. Firmware verification has no such trusted substrate. The candidate malware lives below the OS, on processors with their own execution contexts, and can mediate the very interfaces a scanner would use to read it.

### 1.2 The root-of-trust circularity (the wall)
A resident implant in SMM or the ME can:
- intercept and *virtualize* a software SPI read, returning a pristine stored image while the physical flash holds the implant;
- forge the values of the very lock/config registers a scanner reads to assess protection;
- detect a known scanner (CHIPSEC, flashrom, or our own binary) and go quiescent or feed clean data.

Therefore any answer a purely-software, on-host scanner derives about firmware *may be a lie authored by the thing it is hunting.* This is not an engineering deficiency to be fixed; it is a property of the trust topology.

### 1.3 The everyman is unprotected — and the threat has commoditized
Nation-state firmware-implant capability (NSA ANT catalog, 2013–14: `IRATEMONK` HDD-firmware implant, `DEITYBOUNCE`/`SWAP` BIOS/SMM, `SOUFFLETROUGH`) has descended the food chain. Concrete proliferation line: Hacking Team's **VectorEDK** UEFI bootkit leaked in 2015 → **MosaicRegressor** (2020) was built directly from it. **LoJax** (APT28, 2018) was the first in-the-wild UEFI rootkit; **MoonBounce** (APT41, 2022) modifies an existing `CORE_DXE` module rather than adding one; **BlackLotus** (2022–23) is a Secure Boot–bypassing UEFI bootkit **sold on crime forums for ~$5k**. The capability that was once ANT-catalog exotic is now purchasable crimeware. Meanwhile consumer AV protects only the OS.

### 1.4 Existing defenses fall into two buckets, neither of which serves this user
1. **Welded to one vendor's silicon:** HP Sure Start (Endpoint Security Controller), Dell SafeBIOS, Intel PFR (CPLD on the SPI bus), Microsoft/Google Cerberus/OpenTitan, AMI Tektagon (RoT MCU). These are robust *and* require the vendor's hardware; they protect only the vendor's own firmware, and the strong ones are datacenter/commercial silicon absent from most client boards.
2. **Closed enterprise agents that trust host-mediated reads:** Eclypsium, Binarly. Cross-vendor, but enterprise-priced, opaque, cloud-dependent, and — critically — they report what the host hands them and **do not fail closed** when the collector could have been blinded.

**The unoccupied intersection:** vendor-neutral + open/auditable + fail-closed + off-host verdict + no new silicon + the everyman's already-shipped Windows box. SPI-Eyes targets exactly that intersection.

### 1.5 Prior art that validates the core pattern
**Dell SafeBIOS** already captures the BIOS on the host but performs the *comparison off-host in Dell's cloud*, so an on-host implant cannot fake the "match." This proves the off-host-verdict pattern works in software today. SPI-Eyes generalizes it: replace "Dell's opaque cloud, Dell hardware only" with an auditable, vendor-neutral reference corpus and a public transparency log.

---

## 2. Threat Model

### 2.1 Adversary capability (design assumption)
We assume the strongest realistic software adversary:
- **Resident at ring -2 (SMM) and/or ring -3 (Intel ME / AMD PSP)** before the scan runs.
- **Has read the SPI-Eyes source** (it is open); knows exactly how each probe works.
- **Is watching the scan execute** and may behave differently while observed (scanner-aware quiescence).

We do **not** assume the adversary has broken cryptography, nor that they have compromised a genuine hardware root of trust (TPM/DRTM) *before it measured* — those boundaries are where earned CLEAN becomes possible (§3, §5).

### 2.2 In-scope stores (the writable non-volatile attack surface)
Host UEFI/SPI flash; SMM/SMRAM; Intel ME / AMD PSP regions; PCI/PCIe option ROMs; UEFI NVRAM variables; the drive-controller firmware of HDDs/SSDs; the HPA/DCO hidden areas of disks; TPM / measured-boot state.

### 2.3 Explicitly out of scope
- **Attacker-added hardware implants** (e.g., ANT `COTTONMOUTH` USB, `GINSU`/`BULLDOZER` PCI). Rationale: if an adversary has soldered a second processor onto the board, the box is physically owned and no host-side software has purchase.
- **RF retro-reflectors** (`RAGEMASTER`, `SURLYSPAWN`): passive analog side channels; not firmware; never touch the network.
- **Pre-delivery supply-chain interdiction where no clean baseline ever existed.** SPI-Eyes can detect drift and known-bad, but "verify-then-trust from a clean state" has no clean state to start from if the machine arrived dirty. We state this limit rather than paper over it.

### 2.4 Two audiences
- **Everyman:** threatened by the commodified/inherited tier (LoJax-, MosaicRegressor-, BlackLotus-class, TrickBoot-style firmware recon). This tier is largely **not** stealthed against firmware scanners because their victims run none — so honest software detection has real, immediate teeth here.
- **High-value / state-tier target:** threatened by the paranoid top tier that *does* actively hide. Here SPI-Eyes will honestly return CANNOT-VERIFY often, and the value is (a) that honesty, (b) the hardware-anchored escalation path (DRTM quote, external SPI read).

---

## 3. The Impossibility We Accept

**Claim (informal theorem).** *On a host whose lowest privileged execution layer is controlled by an adversary, no purely-software measurement performed by that host can be guaranteed to reflect the true state of firmware, because the adversary can interpose on every interface the measurement uses.*

Consequences we accept and design around:
1. We never sell "software proved your firmware clean." That promise is a lie at the top tier and poisons trust everywhere.
2. Earned CLEAN requires **evidence rooted outside the adversary's control** — specifically (a) a fresh, nonce-bound TPM quote over a **Dynamic Root of Trust for Measurement (DRTM)** chain (Intel TXT / AMD SKINIT, surfaced on Windows via System Guard / Secure Launch), or (b) an **external hardware read** of the SPI flash performed off the CPU.
3. Everything else is, at best, corroborating; if it *could* have been blinded, it is CANNOT-VERIFY.

Caveat we also state: even a DRTM/TPM quote attests only what was *measured*; if the Root of Trust for Measurement was compromised before it measured, PCRs reflect an attacker-chosen value. And DRTM does not by itself re-measure SMM (absent an STM, which is nearly never deployed), so a DRTM-earned CLEAN is scoped to "clean above SMM." We do not overclaim it.

---

## 4. Core Invariant: Never a False Clean

Three verdicts, and only three:

| Verdict | Meaning |
|---|---|
| **CLEAN (Above-SMM)** | Positive match to a trusted reference **and** hardware-rooted evidence (external SPI read, or a DRTM quote **with a verified event log** per R2) — scoped to the domain the evidence actually covers (DRTM **excludes SMM**). Unconditional CLEAN requires SMM locks validated *and* a clean external dump (R1). Earned, never assumed. |
| **ANOMALOUS** | Positive evidence of deviation: a known-bad match, a structural anomaly, a drift from baseline, an intrusion tell (debug interface enabled, hidden capacity present, region unexpectedly unlocked). |
| **CANNOT-VERIFY** | The probe could not obtain trustworthy evidence — it was blinded, the region was read-denied, the only source was self-reporting, or no reference exists. **This is where all blindable probes fail closed.** |

**Design rules that enforce the invariant:**
- **Blinding is signal.** A region that reads back as all-`0xFF` because access was denied is CANNOT-VERIFY, never "empty/clean." A read the implant had to block reads as CANNOT-VERIFY.
- **Self-reporting components never earn CLEAN by their own word.** The ME reporting its own version, a disk controller reporting its own firmware revision, or SRTM PCRs (0–7) taken on a possibly-owned host are corroborating only.
- **Every probe carries a `could-this-have-been-blinded` flag and a `max-earnable-verdict`.** A probe whose flag is set cannot contribute to CLEAN.
- **The adversary's reachable outcome is bounded to CLEAN→CANNOT-VERIFY.** No subversion path may turn an infection into CLEAN. This is the property to attack in review (§14, C1).

The AK-47 analogy is the design ethos: tolerate a hostile, degraded, partially-compromised environment and still perform the one job — *honest verdict or honest refusal, never a false all-clear.* It jams safe; it does not fire blanks and call them live.

---

## 5. The Evidence Lattice

Every evidence source has a **maximum earnable verdict.** This is the spine of the tool.

| Evidence source | Read path | Spoofable by ring -2/-3? | Max earnable verdict |
|---|---|---|---|
| Fresh nonce-bound **DRTM TPM quote** vs enrolled baseline | Hardware-measured, TPM-signed | No (if RTM was clean at measure time) | **CLEAN** (scoped above SMM) |
| **External hardware SPI read** (powered-off) vs internal read | Off-CPU | No | **CLEAN / ANOMALOUS** (SPI contents) |
| **CHIPSEC** reset-latched lock/fuse reads (FLOCKDN, D_LCK, SMRR, Boot Guard SACM_INFO, PSB fuse) | Kernel driver → MMIO/MSR/PCI | Read path interceptable | **Susceptibility only**; infection = CANNOT-VERIFY |
| Image analysis (fwhunt-scan, UEFITool) on a software dump | Inherits dump provenance | Only flags *known*-bad | verdict inherits the dump's trust |
| SRTM PCRs (0–7) via TBS, Secure Boot variables, dbx currency | OS/firmware-reported | Yes | Advisory / susceptibility |
| **HSTI** (OEM self-graded security bits) | OS/ACPI | Yes, doubly (self-report + OS path) | Weak corroboration |
| OS APIs (`Confirm-SecureBootUEFI`, `Win32_Tpm`, `Win32_DeviceGuard`, MSInfo) | OS | Yes | Advisory |

**The two load-bearing anti-spoof primitives** (the only things that manufacture CLEAN):
1. **External-vs-internal SPI read divergence.** Dump externally (hardware programmer, powered-off) and internally (CHIPSEC/flashrom). Identical → the software path is not being lied to for that region. Different → the OS-mediated read is being filtered → ANOMALOUS. This is the single most valuable primitive for catching a lying implant with open tools.
2. **Nonce-fresh DRTM TPM quote vs baseline.** A quote signed by the TPM's Attestation Key over a DRTM-measured chain cannot be forged by ring-0/ordinary ring-2. Demand the *quote* (with a fresh nonce), not just the event log; verify the event log reconstructs the PCRs; confirm measured components hash to known-good.

**Reset-latched nuance:** locks like FLOCKDN, D_LCK, SMRR, and Boot Guard fuse state are *reset-latched real silicon state* — hard to forge at runtime — but the **read** of them is still interceptable, and (importantly) they answer **susceptibility, not infection**. A misconfigured/unlocked read is a *high-confidence* susceptibility signal (an adversary has little reason to forge weakness); a locked read is weak evidence of cleanliness.

---

## 6. Architecture

### 6.1 Pipeline
```
enumerate present stores  →  per-store PROBE adapter  →  TELLS / anomaly layer  →  fail-closed VERDICT
   (what processors &          (read via best available    (known-bad + structural   (per store: CLEAN /
    NV stores exist)            path; record trust tier)    + intrusion tells)         ANOMALOUS / CANNOT-VERIFY,
                                                                                        + confidence + blind-flag)
                                                                       ↓
                                              off-host aggregation → signed EAT verdict → transparency log
```

### 6.2 Two verdict layers, never conflated
- **SUSCEPTIBILITY** — "are the vendor locks set?" (CHIPSEC config: BIOS_CNTL/BLE/SMM_BWP, PRx coverage, FLOCKDN, D_LCK, SMRR, SMM_Code_Chk_En, Boot Guard/PSB provisioning, Secure Boot on, dbx currency). Answers *exposure*, not *infection*. A green here must **never** be presented as "not infected."
- **INFECTION** — "is something actually resident?" Requires content evidence (external read, DRTM-measured hashes, known-bad matches, baseline drift). Defaults to CANNOT-VERIFY unless hardware-rooted.

### 6.3 Per-store adapters (the pluggable engine)
Each adapter implements `read → verify → verdict` and declares its `max_earnable_verdict` and `blindable` flag. New implant class = new adapter, not a rewrite. Adapter set (initial): SPI/UEFI, SMM, Intel ME, AMD PSP, option ROM, NVRAM, drive-controller firmware, HPA/DCO, TPM/measured-boot.

### 6.4 Off-host verdict & non-suppressibility
Following Dell SafeBIOS's proven pattern and Microsoft System Guard's "evaluate a signed statement off-box" model: the verdict decision is designed to be reproducible off the potentially-compromised host, the raw captured image is retained for forensic diff, and the **verdict is emitted as a signed, nonce-bound EAT token** whose hash is published to a transparency log (Rekor). Consequence: a resident implant cannot *silently* suppress an ANOMALOUS verdict — suppression leaves a gap in an append-only log.

---

## 7. Standards Alignment

SPI-Eyes is a software realization of published requirements, not an invention:

- **NIST SP 800-193 (Platform Firmware Resiliency): Protect / Detect / Recover.** SPI-Eyes implements the **Detect** pillar in software for machines whose OEM shipped a weak or absent Root of Trust for Detection. 800-193's Detect requirement that a platform **"shall not silently continue"** on unverifiable state is our fail-closed invariant, restated as a standard. We provide **Recover** only as *advisory* (we do not reflash from software — unsafe; we point to the authenticated OEM golden image / capsule and the dbx/Secure Boot remediation).
- **NIST SP 800-147 (BIOS Protection):** Root of Trust for Update → genuine firmware traces to an OEM signature; unsigned/self-signed/broken-chain firmware is ANOMALOUS.
- **NIST SP 800-155 (BIOS Integrity Measurement, draft):** the RTM-measures-into-TPM-and-compares-to-Reference-Integrity-Measurements model — our known-good corpus, standardized.
- **TCG PC Client Platform Firmware Profile:** defines which PCR measures what (PCR0 firmware, PCR2 option ROMs, PCR4 boot loader, PCR7 Secure Boot policy, PCR17–22 DRTM) and the event-log format we parse.
- **IETF RATS (RFC 9334) + EAT (RFC 9711) + CoRIM (draft):** SPI-Eyes is a RATS *Attester* (and embeds a *Verifier*); the verdict is an **EAT** token; reference values are expressed as **CoRIM**. This makes our output and corpus legible to any RATS-aware consumer.

---

## 8. Build Map — We Are an Orchestrator

The heavy lifting exists and is maintained. Our per-capability novelty is thin; our value is composition + verdict semantics. We wrap, we do not reinvent ([build-engines principle]).

| Role | Wrap / integrate | License | Notes |
|---|---|---|---|
| Susceptibility probes (SPI/SMM/ME registers, SPI dump) | **CHIPSEC** | GPL-2.0 | Primary engine. Its "PASS" maps to CANNOT-VERIFY-leaning, **not** CLEAN. Needs a Windows kernel driver (signing risk — see §12). |
| **CLEAN-capable TPM quote + event-log replay (Windows)** | **go-attestation** + **go-tpm-tools** | Apache-2.0 | The only software path to earned CLEAN; Windows-native via TBS. |
| Lower-level SMM/SMI primitives (esp. AMD) | IOActive **Platbox** | see repo | Selective; kernel driver, same signing caveat. |
| Image carving / UEFI parsing | **binwalk v3** (Rust, Windows), **UEFITool/UEFIExtract**, **uefi-firmware-parser** | MIT / BSD-2 / MIT | binwalk v3 is a Rust rewrite with Windows support. |
| Intel ME / AMD PSP parsing | **MEAnalyzer**, **PSPTool** | informal / GPL-3.0 | Do not rebuild ME/PSP format knowledge. |
| Known-bad rules + firmware→SBOM | **fwhunt-scan** + **FwHunt** rules | Apache/GPL | Pure-Python, Windows-friendly. A *miss* is CANNOT-VERIFY, never CLEAN. |
| Known-good corpus seed | **LVFS/fwupd** metadata + **coreboot** reproducible hashes | LGPL / GPL | LVFS = largest public signed-hash source; coreboot = independently *rebuildable* hashes. |
| CVE matching | **Syft/Grype**, **cve-bin-tool** | Apache/GPL | Component → CVE once an image is unpacked. |
| Verdict token / reference schema / transparency | **EAT (RFC 9711)**, **CoRIM**, **Veraison** libs, **Rekor** | RFC / Apache-2.0 | Signed nonce-bound verdict; tamper-evident log. |
| Drive firmware / HPA-DCO | **smartmontools**, **nvme-cli** | GPL | Self-reported → CANNOT-VERIFY; capacity/DCO mismatch → ANOMALOUS. |
| Reference logic (read, don't ship) | AMI **Tektagon OpenEdition**, **OpenTitan** Security Model | open | Auditable specs of correct 800-193 Detect logic. |

Ecosystem synergy (internal): an elevated local Windows daemon (project *Actuator*) is a natural privileged host for the driver-level operations.

---

## 9. The Corpus

Known-good schema: **CoRIM** (CoMID for hardware/firmware module reference values, CoSWID for software identity). Tiered by trust:

- **Tier 0 — verifiable:** coreboot reproducible-build hashes. You can independently rebuild and derive the same hash; highest trust; small platform set.
- **Tier 1 — vendor-signed:** LVFS/fwupd SHA-256 hashes (primary volume), OEM signed capsules where obtainable, Pixel Binary Transparency (Pixel-scoped). Verify signatures on ingest; record provenance per entry.
- **Tier 2 — first-seen historical baseline:** the earliest measurement recorded for a SKU/version, before wide exposure; drift from it is ANOMALOUS.
- **Tier 3 — population consensus (anomaly-only, the moat):** the majority image for identical SKUs. **Never elevates to CLEAN** — a majority-infected SKU (supply-chain/interdiction) would otherwise self-certify (R3). A consensus-only match ⇒ CANNOT-VERIFY with "matches N% of SKU" context; outliers ⇒ ANOMALOUS. A **canary set** of known-good images (coreboot-reproducible / external-read-verified) is monitored for consensus drift as a contamination alarm.

**Honest coverage statement (must surface in UX):** public known-good firmware-hash data is real but **partial and heterogeneous**. LVFS is the backbone but carries *update-artifact* hashes, not fine-grained per-component boot measurements, and skews to Linux-friendly OEMs. TCG RIM's promised per-device golden values are effectively absent in the consumer market today. Therefore population consensus is *necessary*, not optional. The tool must clearly distinguish "matched an authoritative reference" from "matched population consensus" from "no reference → indeterminate."

Tamper-evidence: keep the corpus and verdict emissions in an append-only transparency log (Rekor for zero-ops public logging; Trillian for a dedicated firmware-measurement log). Reference the log checkpoint + inclusion proof inside the EAT verdict.

---

## 10. Hardware Gold Tier (Optional, for Power Users / High-Value Targets)

The external SPI read is the only CLEAN-capable evidence for flash *contents*. It is cheap and buildable now.

- **Recommended default (~$39):** **Tigard** (FT2232H, fully open) + genuine SOIC-8 clip + **flashrom**. Proper level-shifting eliminates the #1 failure mode (5V-on-3.3V damage / garbage reads).
- **Cheapest (~$35):** **Raspberry Pi Pico + pico-serprog** (UF2, ~$4) + **genuine Pomona 5250 clip** (~$30) + flashrom.
- **Pro (~$139 / ~$275):** Glasgow Interface Explorer (open, versatile) or Dediprog SF100 (turnkey, best Windows GUI, real in-system reset-hold pins) — for WSON/QFN packages and high-value targets.

**Procedure (scripted):** power target **off** → clip the flash → `flashrom -r ext.bin` → read 3× and hash-compare for stability → diff `ext.bin` against the host's internal software dump. Divergence = implant flag.

**Honest constraints:** the trustworthy read is **powered-off and sequential** (software read → shutdown → external read → offline diff); we cannot promise a *live simultaneous* compare. In-circuit reads risk bus contention (the running host drives the bus) and back-powering the board through the flash rail; genuine clips matter (clone clips are the top cause of unstable reads); WSON/QFN packages defeat cheap clips.

---

## 11. Explicitly Rejected / Scoped-Out Approaches

Stating what we deliberately do **not** do is part of soundness.

- **Timing-based / software-based attestation ("make the lie cost measurable time") — REJECTED for verdicts.** Pioneer, SWATT, VIPER are research-only and defeated in practice (e.g., 2024 debug-register bypass). Modern x86 nondeterminism — out-of-order execution, Turbo/thermal frequency scaling, caches, SMT, SMM interruptions, DVFS, multi-core — swamps the microsecond-scale latency an interception adds, and the adversary can exploit the same features (proxying, spare cores) to hide cost. The research field itself abandoned pure timing for hardware roots. At most a **non-binding heuristic tripwire** later; it may **never** produce CLEAN.
- **Passive SPI bus-watch at boot speed — SCOPED OUT of v1.** Boot commonly uses fast/dual/quad SPI at 33–133 MHz, overrunning cheap MCUs (RP2040 PIO) and small FPGAs. The only turnkey "watch what firmware does" path is *emulation* (spispy / Dediprog em100), which *substitutes* the flash rather than observing the suspect chip. Opt-in research module for power users who own the gear; not core.
- **Reflashing / prevention as the primary mode — OUT.** Boot-integrity/anti-evil-maid tools (Heads, safeboot, Qubes AEM, coreboot/vboot) require owning and modifying the boot chain. Our user cannot reflash a locked OEM machine and wants *detection*. Same problem space, opposite posture.
- **Claiming coverage of non-host firmware we cannot reach (BMC/iLO, NIC, GPU, EC, Thunderbolt) — we DECLARE it uncovered** rather than imply whole-platform clean. (iLOBleed-class implants live here.)

---

## 12. The Two Existential De-Risking Questions

Before building the engine, two unknowns determine whether the tool can *ever* leave CANNOT-VERIFY on a given machine. They must be tested on real target hardware first.

- **Q1 — Driver loadability.** Can the CHIPSEC (and/or Platbox) unsigned/attestation-signed kernel driver load on a locked Windows 11 box with HVCI / Memory Integrity / Driver Signature Enforcement active? If not, the entire susceptibility layer and software SPI dump are unavailable, and *loading the driver is itself observable to a resident implant.*
- **Q2 — Earned-CLEAN reachability.** Does the machine expose **DRTM / System Guard / Secure Launch** and a usable **nonce-bound TPM quote**? If not, there is *no software path to CLEAN* on that machine and every verdict collapses to CANNOT-VERIFY — which we want to know **before** building the tower.

### First deliverable: the Capability Probe (read-only, safe)
The first slice is not "enumerate the stores"; it is a **capability/reachability probe** answering, per machine: *"What is the best verdict this machine can ever earn?"*
- TPM present? nonce-bound quote obtainable (via go-tpm-tools/TBS, **no kernel driver**)?
- DRTM / System Guard / Secured-core present (`Win32_DeviceGuard`)?
- CHIPSEC driver loadable, or blocked by HVCI?
- Measured-boot log readable (TBS `Tbsi_Get_TCG_Log_Ex`)?
- No-driver evidence tier: Secure Boot state + **dbx currency vs known bootkit revocations**, drive firmware version, **HPA/DCO** presence.

Output: the three-verdict lattice with a `max_earnable_verdict` per source **and** a top-line *evidence ceiling* for the machine. This is honest, unique (no other tool reports your evidence ceiling), and it greenlights or bounds the whole architecture before further investment.

---

## 13. Appendix A — Red→Green Catalog

Every adversary evasion maps to a detection opportunity. Meta-rule: **when the enemy blinds a probe, the blinding is the signal → CANNOT-VERIFY, never CLEAN.**

| # | Evasion (RED) | Tell / cross-check (GREEN) | Honest verdict when blinded |
|---|---|---|---|
| 1 | SMM/ME virtualizes SPI reads, returns clean image | External-vs-internal dump divergence; anomalous SMI dwell (RDTSC / MSR 0x34) | software-only dump ⇒ CANNOT-VERIFY |
| 2 | Descriptor read-lock → region reads `0xFF` | Map flash-descriptor master-read perms *before* interpreting bytes | denied region ⇒ CANNOT-VERIFY |
| 3 | CHIPSEC lock registers spoofed clean | Read via independent methods; confirm SMRR/D_LCK actually cover SMRAM | disagreement ⇒ ANOMALOUS |
| 4 | ME lies about its own firmware/version | HECI version vs vendor DB + external read; **DCI/JTAG enabled = intrusion tell**; ME downgraded below INTEL-SA-00086 fix | ME-only source ⇒ CANNOT-VERIFY; downgrade/DCI ⇒ ANOMALOUS |
| 5 | PCR replay / measured-boot spoof | nonce-fresh quote; event log must reconstruct PCRs; prefer DRTM (PCR17+) | log absent/inconsistent ⇒ CANNOT-VERIFY; PCR≠reported-fw ⇒ ANOMALOUS |
| 6 | In-module hook (MoonBounce/CosmicStrand), no new file | per-module content hash + CFG diff vs reference (not module count/size) | unmatched module ⇒ ANOMALOUS |
| 7 | Signed-vulnerable reuse / MOK enroll (BlackLotus, Baton Drop) | hash ESP bootloaders vs current dbx/SBAT; audit PK/db/dbx/MokList for foreign certs | known-vuln binary / foreign MOK ⇒ ANOMALOUS |
| 8 | LogoFAIL (malicious boot-logo parser exploit) | hash boot-logo region; flag non-vendor logo / patched parser | custom logo ⇒ ANOMALOUS |
| 9 | Option ROM implant / re-infector | enumerate + hash all option ROMs vs vendor; PCR2 cross-check | unknown ROM ⇒ ANOMALOUS |
| 10 | HDD/SSD controller firmware implant (IRATEMONK) | firmware-revision pin vs vendor; canary-sector write/read-back | unknown rev ⇒ ANOMALOUS; unverifiable ⇒ CANNOT-VERIFY |
| 11 | HPA/DCO hidden area | `READ NATIVE MAX EXT` vs IDENTIFY capacity; NVMe namespace vs total | hidden capacity ⇒ ANOMALOUS, contents CANNOT-VERIFY |
| 12 | Scanner-aware dormancy (adversary read our source) | don't announce; rotate probe method/timing; independent cross-checks; measure read *cost* | any single spoofable probe ⇒ corroborate or CANNOT-VERIFY |

---

## 14. Adversarial Review Guide — Claims Ledger

**Reviewers: attack these.** Each claim has a confidence level and an impact rating. A confirmed refutation of a *high-impact* claim changes the architecture; note it explicitly.

- **C1 — [high-impact, confidence: medium-high]** The invariant is enforceable: no subversion path available to a ring -2/-3 adversary can convert a real infection into a **CLEAN** verdict; the worst they achieve is CLEAN→CANNOT-VERIFY. *Attack:* find a probe or aggregation step where a blinded/forged input can produce CLEAN. Pay special attention to the DRTM quote path (can a pre-measurement implant produce a quote that both verifies *and* hides itself?) and to any place susceptibility "locks set" could leak into an infection CLEAN.
- **C2 — [high-impact, confidence: medium]** Earned CLEAN is actually *reachable* on a meaningful fraction of commodity Windows machines — i.e., DRTM/System Guard + a verifiable nonce-bound TPM quote is available often enough that the tool isn't perpetually CANNOT-VERIFY. *Attack:* argue from Secured-core prevalence that non-Secured-core boxes (the majority?) have no earned-CLEAN path, making the tool's positive output near-useless for the everyman. Quantify if possible.
- **C3 — [high-impact, confidence: medium]** The external-vs-internal SPI read divergence check reliably distinguishes "implant virtualizing reads" from benign causes (shadowing, descriptor read-locks, contention). *Attack:* construct benign scenarios that produce divergence (false ANOMALOUS) or an implant strategy that produces *identical* internal/external reads (false negative) — e.g., an implant that only activates post-read, or lives in a region the external read also can't interpret.
- **C4 — [medium-impact, confidence: high]** Timing/software-based attestation cannot be a sound signal on modern x86. *Attack:* present a modern (post-2020) result demonstrating reliable timing-based firmware-integrity attestation on a general OoO x86 host. (We believe this does not exist.)
- **C5 — [medium-impact, confidence: medium]** The CHIPSEC kernel driver can be loaded on a representative locked Win11 24H2 + HVCI machine via attestation-signing (without test-signing). *Attack:* show it cannot, or that doing so requires weakening the box (test-signing) enough to matter. (This is Q1; genuinely uncertain.)
- **C6 — [medium-impact, confidence: medium-high]** Publishing verdict hashes to a transparency log meaningfully prevents *silent* suppression of ANOMALOUS verdicts by a resident implant. *Attack:* the implant blocks the network / the logging call before emission, leaving no gap because no entry was ever attempted; discuss whether "expected-but-absent heartbeat" logging closes this and at what cost.
- **C7 — [medium-impact, confidence: medium]** A population-consensus corpus can flag outliers without an authoritative reference, *and* cannot be poisoned into hiding a widespread implant. *Attack:* a supply-chain or update-time implant that infects the *majority* of a SKU becomes the "consensus clean." Address how consensus distinguishes majority-legitimate from majority-infected.
- **C8 — [low-impact, confidence: high]** The heavy-lifting components (CHIPSEC, go-attestation, UEFITool, MEAnalyzer, PSPTool, fwhunt-scan, LVFS) exist, are maintained, and are wrappable on Windows. *Attack:* identify a wrap target that is abandoned, Linux-only, or license-incompatible with an open release. (FwAnalyzer/ByteSweep are already known-dead and excluded.)
- **C9 — [high-impact, confidence: medium]** The scope exclusions (hardware implants, RF, no-clean-baseline interdiction) do not gut the value proposition — i.e., the in-scope, software-delivered firmware-persistence threat is large and real enough to matter. *Attack:* argue the residual threat after exclusions is small or that the excluded classes dominate real-world compromise.
- **C10 — [medium-impact, confidence: medium-high]** "Off-host verdict" is achievable in a way that materially raises trust for a *single-machine consumer* with no second trusted device or cloud. *Attack:* without Dell's cloud or an enterprise verifier, where does the off-host evaluation actually run for a lone user, and is a self-emitted EAT on the same host meaningfully "off-host"?

### Known open problems (we already believe these are unsolved)
1. **No clean baseline for interdicted machines** — verify-then-trust has no starting point if the machine arrived dirty.
2. **Non-host firmware coverage** (BMC/NIC/EC/GPU/TB) is out of reach of a host-side Windows tool.
3. **DRTM does not re-measure SMM** absent an STM (rarely deployed) — earned CLEAN is scoped "above SMM."
4. **Public known-good coverage is partial** — population consensus is load-bearing and unproven at low adoption.
5. **Driver-load observability** — the act of loading our kernel driver is visible to a resident implant, which may quiesce.

---

## Appendix B — Primary Sources

**Threat / red:** ESET LoJax (https://web-assets.esetstatic.com/wls/2018/09/ESET-LoJax.pdf); Kaspersky MosaicRegressor (https://securelist.com/mosaicregressor/98849/), MoonBounce (https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/), CosmicStrand (https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/), Equation Group HDD firmware (https://www.kaspersky.com/blog/equation-hdd-malware/7623/); ESET BlackLotus (https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/); Binarly LogoFAIL (https://www.binarly.io/blog/the-far-reaching-consequences-of-logofail); Positive Technologies Intel ME (http://blog.ptsecurity.com/2018/11/what-we-have-learned-about-intel-me.html); Zaddach et al. stealth HDD backdoor, ACSAC 2013 (https://hal.science/hal-00869263/document).

**Blue / tools:** CHIPSEC (https://github.com/chipsec/chipsec); go-attestation (https://github.com/google/go-attestation), go-tpm-tools (https://github.com/google/go-tpm-tools); fwhunt-scan (https://github.com/binarly-io/fwhunt-scan), FwHunt (https://github.com/binarly-io/FwHunt); UEFITool (https://github.com/LongSoft/UEFITool), uefi-firmware-parser (https://github.com/theopolis/uefi-firmware-parser), MEAnalyzer (https://github.com/platomav/MEAnalyzer), PSPTool (https://github.com/PSPReverse/PSPTool); binwalk (https://github.com/ReFirmLabs/binwalk); flashrom (https://flashrom.org/); Keylime (https://keylime.dev); Veraison (https://github.com/veraison).

**OEM / silicon:** Eclypsium SPI write protections (https://eclypsium.com/blog/firmware-security-realizations-part-3-spi-write-protections/); Speed Racer VU#766164 (https://www.kb.cert.org/vuls/id/766164/); Synacktiv SMM Code Check (https://www.synacktiv.com/en/publications/code-checkmate-in-smm); MSI Boot Guard key leak (https://www.bleepingcomputer.com/news/security/intel-investigating-leak-of-intel-boot-guard-private-keys-after-msi-breach/); IOActive AMD PSB (https://www.ioactive.com/exploring-amd-platform-secure-boot/); Invisible Things TXT attacks (http://invisiblethingslab.com/resources/bh09dc/Attacking%20Intel%20TXT%20-%20paper.pdf); HP Sure Start whitepaper (https://h10032.www1.hp.com/ctg/Manual/c06216928.pdf); Dell SafeBIOS Image Capture (https://www.dell.com/support/manuals/en-us/bios-verification/biosverification/image-capture); Intel PFR (https://www.intel.com/content/www/us/en/products/docs/processors/xeon/platform-firmware-resilience.html); AMI Tektagon OpenEdition (https://www.ami.com/blog/2022/10/18/ami-contributes-its-tektagon-openedition-platform-root-of-trust-firmware-code-base-to-the-open-compute-project/); OpenTitan (https://opentitan.org/); MS System Guard (https://www.microsoft.com/en-us/security/blog/2018/04/19/introducing-windows-defender-system-guard-runtime-attestation/).

**Standards / attestation / transparency:** NIST SP 800-193 (https://csrc.nist.gov/pubs/sp/800/193/final), 800-147 (https://csrc.nist.gov/pubs/sp/800/147/final), 800-155 draft (https://csrc.nist.gov/pubs/sp/800/155/ipd); TCG PC Client Firmware Profile (https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/); RATS RFC 9334 (https://datatracker.ietf.org/doc/rfc9334/); EAT RFC 9711 (https://datatracker.ietf.org/doc/rfc9711/); CoRIM draft (https://datatracker.ietf.org/doc/draft-ietf-rats-corim/); Rekor/Sigstore (https://github.com/sigstore/rekor); Pixel Binary Transparency (https://developers.google.com/android/binary_transparency/pixel_overview); coreboot reproducible builds (https://tests.reproducible-builds.org/coreboot/coreboot.html); CISA/NSA UEFI Secure Boot 2025 (https://media.defense.gov/2025/Dec/11/2003841096/-1/-1/0/CSI_UEFI_SECURE_BOOT.PDF); NSA firmware tooling (https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance).

**Hardware gold tier:** Tigard (https://www.crowdsupply.com/securinghw/tigard); pico-serprog (https://github.com/stacksmashing/pico-serprog); Glasgow (https://www.crowdsupply.com/1bitsquared/glasgow); Dediprog SF100 (https://www.dediprog.com/product/SF100); spispy (https://trmm.net/Spispy/); em100pro (https://www.dediprog.com/product/EM100Pro-G3).

**Rejected-approach evidence:** Pioneer (https://users.ece.cmu.edu/~adrian/projects/pioneer/); SWATT (https://netsec.ethz.ch/publications/papers/swatt.pdf); VIPER (https://netsec.ethz.ch/publications/papers/viper-ccs11.pdf); 2024 software-attestation bypass (https://www.tandfonline.com/doi/full/10.1080/09540091.2024.2306965).

---

## Accuracy caveats (stated, not hidden)
1. **No defensible public statistic** exists for the prevalence of SPI-unlocked / FLOCKDN-clear machines; Eclypsium's material is qualitative. Treat "common historically" as the honest claim; do not cite a fabricated percentage.
2. **CHIPSEC Windows driver signing** on current Win11 + HVCI needs live verification (this is Q1/C5).
3. **DRTM/System Guard reachability** is per-machine and unverified until the capability probe runs (Q2/C2).
4. Exact **CHIPSEC module names** for Intel Boot Guard vary by version; the stable primitive is the MSR 0x13A (SACM_INFO) read.
5. A few source items dated 2025–2026 were surfaced by search and should be re-verified before they become detection rules.
