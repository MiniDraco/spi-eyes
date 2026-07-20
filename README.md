# SPI-Eyes

**Firmware antivirus, but different.** A vendor-neutral, **fail-closed** firmware-integrity
verifier for commodity Windows PCs — a software realization of the NIST SP 800-193
*Detect* pillar for the machines the silicon root-of-trust never reached.

- Full design + threat model + adversarial review: [`WHITEPAPER.md`](WHITEPAPER.md)
- Build roadmap for contributors / future sessions: [`PLAN.md`](PLAN.md)
- Red-team brief for other engines: [`ADVERSARIAL-PASS.md`](ADVERSARIAL-PASS.md)

## The one idea

You cannot prove a machine is *clean* from software running on top of possibly-compromised
firmware — that's a theorem, not a gap. So SPI-Eyes never claims CLEAN unless CLEAN was
*earned* by hardware-rooted evidence (a DRTM TPM quote, or an external off-CPU SPI read).
Its only verdicts are **CLEAN / ANOMALOUS / CANNOT-VERIFY**, and any probe that could have
been blinded by a resident implant **fails closed to CANNOT-VERIFY, never CLEAN**. The
adversary can only downgrade CLEAN→CANNOT-VERIFY; they can never manufacture a false
all-clear.

## What's built so far — the Capability Probe (Phase 1a)

Read-only, loads **no kernel driver**, writes nothing to firmware. It answers, for *this*
machine: **"what is the best verdict SPI-Eyes could ever honestly earn here?"** — the
*evidence ceiling*. That single honest number is unique; no other tool reports it.

```
# from the spi-eyes/ directory:
python -m capability_probe            # non-elevated: TPM/SecureBoot/dbx -> NOT-ASSESSED
# for the full susceptibility picture, run from an ELEVATED PowerShell:
python -m capability_probe
```

- Zero pip dependencies (Python 3.9+ stdlib + PowerShell/WMI).
- Emits a colored console report and a JSON artifact under `out/`.
- Probes: machine identity (corpus key), TPM presence/kind, DRTM/System Guard/HVCI
  state, measured-boot log, Secure Boot + dbx currency, drive firmware, HPA/DCO
  availability, and a CHIPSEC-driver **loadability assessment** (Q1) — no driver loaded.

### First real result (host `Petra`, Gigabyte B450M DS3H, BIOS F50)
Evidence ceiling = **CANNOT-VERIFY**. No active DRTM/Secure Launch on this AM4 desktop →
**no software path to CLEAN** (external SPI read is the only route). This is the honest,
predicted outcome for a commodity desktop and is exactly why the product's headline
deliverable is the *evidence ceiling + exposure report*, not a green light (WHITEPAPER R6).

## Architecture (this probe is the engine's first vertical slice)

`Evidence` (with a `max_earnable_verdict` ceiling + `blindable` flag) → aggregate under
`V ≤ max(Mᵢ)` → ceiling. New probes/adapters plug in without touching the core. See
[`PLAN.md`](PLAN.md) for the phased path from here to earned-CLEAN.

## Design tenets (enforced in code review)
1. **Never collapse "couldn't check" into a negative.** Access-denied is NOT-ASSESSED, not
   "absent." (This was the first self-inflicted bug the probe caught — keep watching for it.)
2. **Blindable ⇒ cannot contribute to CLEAN.** Every OS-mediated read is `blindable=True`.
3. **Say the ceiling, not a clean bill.** Honesty about our own blind spots is the product.
