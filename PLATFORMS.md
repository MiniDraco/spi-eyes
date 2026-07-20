# SPI-Eyes — Platform SKU Roadmap

Goal: **ubiquity** — Windows, Linux, macOS across x86-64 and ARM. The verdict lattice
(`model.py`) and aggregation (`V ≤ max(Mᵢ)`) are platform-agnostic; each OS gets a
`probes_<os>.py` SKU module with the evidence sources that platform actually exposes,
plus (later) per-SKU ceiling logic. Dispatch is runtime (`probes.py`).

Strategy (per the user): **build Windows first, lock it, then run this doc back and diff**
— port SKU by SKU, adjusting scope honestly where a platform can't do byte-level checks.

## SKU matrix

| SKU | Susceptibility source | Earned-CLEAN path | Content / dump | Status |
|---|---|---|---|---|
| **Windows / x86-64** | WMI (`Win32_Tpm`, `Win32_DeviceGuard`), `Confirm/Get-SecureBootUEFI`, registry; CHIPSEC (driver, **HVCI-gated**) | DRTM via System Guard + go-tpm-tools quote | flashrom `internal` / CHIPSEC dump + external programmer | **1a+1b DONE** |
| **Windows / ARM64** | same WMI surface; CHIPSEC/driver support is thin on WoA; Qualcomm/Pluton specifics | Pluton / System Guard where present | very limited (SoC-gated flash) | planned |
| **Linux / x86-64** | **CHIPSEC native (no signing wall)**, `mokutil --sb-state`, efivars (db/dbx/KEK/PK), `/sys/firmware`, MSR via `/dev/cpu/*/msr` | **tboot / TrenchBoot DRTM** (TXT/SKINIT) + tpm2-tools/go-attestation | **flashrom `internal` (no driver)** + external; fwupd/LVFS known-good; IMA/EVM | planned — **strongest target** |
| **Linux / ARM64** | UEFI-vs-devicetree varies; TPM via tpm2 if present; flashrom depends on SoC | vendor-specific (few open DRTM) | fragmented; per-board | planned (fragmented) |
| **macOS / Apple Silicon (ARM)** | `csrutil status` (SIP), Startup Security Utility policy, `system_profiler`, `nvram`, `spctl` | **Apple-mediated only** (Secure Enclave/iBoot chain) — we report *policy posture*, not independent byte verification | **none** — SPI flash not user-accessible | posture-only SKU |
| **macOS / Intel + T2** | SIP, Secure Boot policy, T2 status | Apple/T2-mediated | T2 gates SPI (no flashrom) | posture-only SKU |
| **macOS / Intel pre-T2** | SIP, EFI vars | limited | some CHIPSEC/flashrom possible | low priority |

## Honest scope shifts by platform
- **Linux is where SPI-Eyes is *most* capable** — CHIPSEC and flashrom run without the
  Windows kernel-driver-signing / HVCI wall (that's our Q1 blocker on Windows). The Linux
  SKU may reach earned-CLEAN and full susceptibility more often than Windows. Prioritize it
  right after the Windows product is locked.
- **macOS is a posture SKU, not a byte-verifier.** On Apple Silicon the firmware is a closed
  vendor root of trust the user cannot read or reflash; "CLEAN" there can only mean "Apple's
  boot policy is at full security + SIP on." We must *say* that, not imply we verified flash.
- **ARM generally** lacks the open external-read ecosystem x86 SPI-NOR enjoys; the hardware
  gold tier (Tigard/flashrom) may not apply. State per-board.

## Porting checklist (per new SKU)
1. Add `probes_<os>.py` with probes returning `Evidence` (same `max_earnable_verdict` +
   `blindable` contract). Reuse `model.py` unchanged.
2. Add per-SKU ceiling logic if the CLEAN path differs (extend `aggregate.py` with a
   platform branch; Windows logic keys on DRTM-running + TPM 2.0).
3. Fill the SKU row above; move status planned → done.
4. Re-run the whitepaper's honesty test: does any probe risk a false CLEAN or collapse
   "couldn't check" into a negative on this platform?

## Cross-platform dependency notes
- **CHIPSEC:** Windows (driver, HVCI-gated) / Linux (native) / UEFI-shell. Not macOS Apple Silicon.
- **flashrom:** Linux native `internal`; Windows needs driver; external programmer is OS-agnostic (USB).
- **TPM/quote:** go-tpm-tools + go-attestation are cross-platform (Windows TBS / Linux `/dev/tpm0`).
- **fwupd/LVFS corpus:** data is OS-agnostic (parse `.cab` + metadata anywhere).
