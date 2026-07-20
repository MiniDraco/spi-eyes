# SPI-Eyes — Firmware Attestation Collector

A **one-shot, read-only** data-capture tool. Its only job: gather the DRTM / TPM /
measured-boot / Secure Boot data needed to build the SPI-Eyes *earned-CLEAN* engine
(Phase 2) from a **Secured-core / System-Guard-capable Windows laptop** — the kind of
machine the main dev box doesn't have.

## For the person running it (the hand-off)

You've been asked to run this on your laptop and send two files back. Here's the deal,
plainly:

- **It is read-only.** Every operation is a `Get-`/read. It does **not** write to your
  firmware, TPM, BIOS, or boot config. It changes nothing.
- **It makes zero network connections.** It writes two files next to itself and stops.
  *Nothing is transmitted by the tool* — you choose what to send, by hand.
- **You can read it first.** It's a plain-text PowerShell script; open it in Notepad.
- **Privacy:** it collects firmware-security *settings* plus your measured-boot logs
  (which can contain machine identifiers). Run it with `-Anonymize` to hash the
  hostname/serials, and review the `.txt` before sharing.

### Run it
1. Right-click **`Collect-FirmwareAttestation.ps1`** → **Run with PowerShell**.
   (It will ask for Administrator via UAC — needed to read the TPM and measured-boot logs.)
   - Blocked by execution policy? Open PowerShell and run:
     `powershell -ExecutionPolicy Bypass -File Collect-FirmwareAttestation.ps1`
   - Privacy-conscious? add ` -Anonymize`
2. It prints what it finds and writes two files in the same folder:
   - `FirmwareAttest-<host>-<timestamp>.json`
   - `FirmwareAttest-<host>-<timestamp>.txt`
3. **Send both files back.** (Skim the `.txt` first if you want to see exactly what's in them.)

That's it — one run, two files, done. No install, no repeat.

## What it captures (and why)
| Section | Data | Why it's needed |
|---|---|---|
| Identity | model / BIOS / CPU / firmware type | context + corpus key |
| **DeviceGuard** | VBS + **DRTM / Secure Launch running?** | the decisive signal: is this box even capable of earned-CLEAN |
| Registry | DeviceGuard / SystemGuard / SecureBoot keys | how DRTM/HVCI is provisioned |
| TPM | version / manufacturer / ready | the attestation root |
| **Measured-boot logs (WBCL)** | raw TCG event logs, base64 | **the crown jewel** — needed to build the event-log parser + PCR reconstruction |
| Secure Boot | state + dbx/db/KEK/PK (base64) | revocation currency + trust surface |
| bcdedit | boot config | Secure Launch / hypervisor flags |
| HSTI | firmware self-report | best-effort corroboration |

## For the developer (what to do with the files)
The `.json` is the machine-readable capture. The **measured-boot WBCL logs** (base64 in
`measured_boot_logs[].base64`) are the priority: decode them and build the TCG event-log
parser + PCR-reconstruction against real data (WHITEPAPER §5 / PLAN Phase 2). Confirm
`deviceguard.DRTM_running == true` before treating a capture as a valid Phase-2 fixture.
Store captures under `spi-eyes/fixtures/` (git-ignored if they contain un-anonymized data).
