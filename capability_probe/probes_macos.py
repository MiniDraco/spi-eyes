"""macOS evidence probes (SKU stub).

macOS is a fundamentally different trust model and the scope must change honestly:

  Apple Silicon (ARM):
    - No user-accessible SPI flash / no CHIPSEC / no flashrom path. The Secure
      Enclave + iBoot + LLB form a vendor root of trust the user cannot inspect
      or reflash. "External SPI read" gold tier does NOT apply the same way.
    - Available signals: `system_profiler SPiBridgeDataType` (T2/Secure Enclave),
      Startup Security Utility policy, SIP state (`csrutil status`), boot policy,
      `nvram` variables. Attestation via DeviceCheck/Secure Enclave is Apple-mediated.
    - Earned-CLEAN here means "Apple's chain verified" -> we can report the boot
      policy posture, not independently verify firmware bytes. State that limit.

  Intel Mac (x86-64) with T2:
    - T2 gates the SPI flash; similar constraints. Some CHIPSEC works pre-T2 only.

  SUSCEPTIBILITY signals we CAN read: SIP status, Secure Boot policy (full/medium/
  none), FileVault, `spctl` (Gatekeeper), kernel extension / system extension posture.

Status: NOT IMPLEMENTED. macOS SKU is posture-reporting, not byte-level verification
(scope-honest). This stub keeps the platform dispatch real.
"""
from __future__ import annotations

from typing import List

from .model import Evidence, Layer, Verdict


def run() -> List[Evidence]:
    return [Evidence("platform_macos", Layer.CAPABILITY,
                     "macOS SKU not yet implemented (see PLATFORMS.md) -- scope is posture-reporting "
                     "(SIP / Secure Boot policy); Apple Silicon firmware bytes are not user-inspectable",
                     Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "n/a")]
