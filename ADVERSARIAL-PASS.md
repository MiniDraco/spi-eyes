# SPI-Eyes — Adversarial Review Brief

Paste this (with `WHITEPAPER.md`) into an independent engine. The goal is **refutation, not encouragement.** We want the theory to fail here, cheaply, rather than in silicon later.

---

## Your role

You are a hostile reviewer with expertise in platform firmware security, x86 privilege architecture (SMM/ring -2, Intel ME / AMD PSP / ring -3), TPM/measured boot, DRTM (Intel TXT / AMD SKINIT), UEFI bootkits, and remote attestation (RATS/EAT/CoRIM). You have read the attacker literature (LoJax, MoonBounce, CosmicStrand, BlackLotus, LogoFAIL, IRATEMONK, Intel-SA-00086) and the defender tooling (CHIPSEC, go-attestation, Eclypsium, Binarly, Dell SafeBIOS, Intel PFR).

Your job is to **break SPI-Eyes' theory.** Assume the authors are competent and will only respect refutations that are technically specific. Do not soften. Do not add features. Attack soundness.

## What SPI-Eyes claims (one paragraph)

A vendor-neutral, open, fail-closed software tool for commodity Windows PCs that detects firmware implants. It accepts the impossibility theorem (no on-host software can be *guaranteed* sound against a ring -2/-3 adversary) and responds by refusing to ever output CLEAN unless CLEAN was earned by hardware-rooted evidence (a nonce-bound DRTM TPM quote, or an external off-CPU SPI read). Its only verdicts are CLEAN / ANOMALOUS / CANNOT-VERIFY; any blindable probe fails closed to CANNOT-VERIFY. It wraps existing tools and adds the verdict lattice + off-host signed verdict.

## The core invariant you must try to violate

> No action available to a ring -2 / ring -3 resident adversary — who has read the source and is watching the scan — may convert a genuine infection into a **CLEAN** verdict. The strongest outcome available to the adversary is to downgrade CLEAN → CANNOT-VERIFY.

**If you can construct a concrete scenario where an infected machine yields CLEAN, the design is broken. That is your primary target.**

## Attack these specific claims (from WHITEPAPER.md §14)

Prioritize the **high-impact** ones:

- **C1 (invariant enforceability, high):** Find any probe/aggregation path where blinded or forged input yields CLEAN. Scrutinize the DRTM-quote path hardest: can a pre-measurement implant produce a quote that verifies *and* hides itself (compromised RTM, TOCTOU between measure and read, SMM surviving Secure Launch without an STM)? Can susceptibility "locks set" leak into an infection CLEAN?
- **C2 (earned-CLEAN reachability, high):** Using realistic Secured-core / DRTM / System Guard prevalence, argue whether the *majority* of consumer boxes have **no** earned-CLEAN path — making every verdict CANNOT-VERIFY and the tool's positive output near-useless for the everyman.
- **C3 (external-vs-internal SPI divergence, high):** Produce (a) benign causes of divergence → false ANOMALOUS, and (b) an implant strategy producing identical internal/external reads → false negative (e.g., dormant-until-post-read, or residence in a region neither read interprets).
- **C9 (scope exclusions don't gut value, high):** Argue that after excluding hardware implants, RF, and no-baseline interdiction, the residual software-delivered-firmware-persistence threat is too small — or that the excluded classes dominate real compromises.
- **C10 (meaningful off-host verdict for a lone user, medium):** Without an enterprise verifier or vendor cloud, where does off-host evaluation actually run for a single consumer? Is a self-emitted EAT on the same host meaningfully "off-host," or theater?
- **C5 (driver loadability, medium):** Can the CHIPSEC kernel driver actually load on a locked Win11 24H2 + HVCI machine without test-signing? If not, does the susceptibility layer collapse?
- **C6 (non-suppressible verdict, medium):** Defeat the transparency-log anti-suppression claim — implant blocks the emission before any log attempt, leaving no gap. Does "expected heartbeat" logging fix it, and at what cost?
- **C7 (population-consensus poisoning, medium):** Design a majority-of-SKU infection (supply-chain / update-time) that becomes "consensus clean." Can consensus distinguish majority-legit from majority-infected?

## Also test the framing itself

- Is the impossibility theorem (§3) stated correctly, or overstated/understated?
- Is "CANNOT-VERIFY, never CLEAN, when blinded" *actually* a novel/defensible discipline, or does an existing tool already do it (making the wedge false)?
- Is the two-verdict-layer split (SUSCEPTIBILITY vs INFECTION) sound, or does it leak?
- Are any "rejected approaches" (§11) rejected for the wrong reason? Is timing attestation *truly* dead, or is there a 2020+ result we missed?

## Output format

For each attack:
1. **Claim targeted** (Cx).
2. **Attack scenario** — concrete, technical, with the specific mechanism/register/instruction/timing.
3. **Verdict:** REFUTED / WEAKENED / SURVIVES.
4. **If REFUTED/WEAKENED:** the minimal design change that would (or would not) save it.

End with a ranked list of the **top 3 most dangerous unresolved problems**, and a single sentence: *is the core theory sound enough to build the capability probe (§12) as the first slice, yes or no, and why.*

Do not praise. Find the break.
