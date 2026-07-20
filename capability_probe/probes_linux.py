"""Linux evidence probes (SKU stub).

Linux is actually the STRONGEST SPI-Eyes target: CHIPSEC runs natively, flashrom
`internal` needs no signed driver, and rich sysfs/TPM surfaces exist. Planned sources
(see PLATFORMS.md):

  CAPABILITY / earned-CLEAN:
    - TPM2 + measured boot: /sys/kernel/security/tpm0/binary_bios_measurements,
      tpm2-tools (tpm2_quote, tpm2_pcrread), go-attestation.
    - DRTM: tboot / TrenchBoot (Intel TXT / AMD SKINIT) -> PCR17+.
  SUSCEPTIBILITY:
    - CHIPSEC native (no driver-signing wall): bios_wp, spi_lock, smm, smm_code_chk.
    - Secure Boot state: mokutil --sb-state; efivars for db/dbx/KEK/PK.
    - Boot Guard: MSR 0x13A via /dev/cpu/*/msr (CHIPSEC).
  INFECTION / content:
    - flashrom -p internal (spoofable) vs external programmer diff.
    - fwupdmgr / LVFS for known-good hashes; IMA/EVM for OS-runtime integrity.
    - hdparm --dco-identify / -N for HPA/DCO; nvme-cli for NVMe fw slots.
    - lspci -vv option ROMs; /sys/firmware/acpi for tables.

Status: NOT IMPLEMENTED. This stub returns a single NOT-ASSESSED marker so the
platform dispatch is real and the SKU is visible on the roadmap.
"""
from __future__ import annotations

from typing import List

from .model import Evidence, Layer, Verdict


def run() -> List[Evidence]:
    return [Evidence("platform_linux", Layer.CAPABILITY,
                     "Linux SKU not yet implemented (see PLATFORMS.md) -- Linux is the strongest target: "
                     "native CHIPSEC + flashrom, no driver-signing wall",
                     Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "n/a")]
