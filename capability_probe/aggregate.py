"""Aggregate probe Evidence into the machine's *evidence ceiling*.

The capability probe's headline answer: given only what this machine exposes,
what is the strongest verdict SPI-Eyes could ever honestly earn here?
Per the invariant (WHITEPAPER §4/§5): V <= max(Mi), and CLEAN is reachable only
from hardware-rooted evidence (DRTM quote today; external SPI read = manual tier).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .model import Evidence, Verdict


@dataclass
class Ceiling:
    verdict: Verdict                       # best earnable *clean-bill* for this machine
    scope: str                             # human note on what that clean would cover
    clean_reachable: bool
    drtm_running: bool
    tpm20: bool
    hvci_running: bool
    susceptibility_flags: List[str] = field(default_factory=list)
    escalations: List[str] = field(default_factory=list)


def _find(evs: List[Evidence], probe: str) -> Optional[Evidence]:
    return next((e for e in evs if e.probe == probe), None)


def compute_ceiling(evs: List[Evidence]) -> Ceiling:
    tpm = _find(evs, "tpm")
    dg = _find(evs, "deviceguard")
    drv = _find(evs, "driver_loadability")

    tpm_assessed = bool(tpm and tpm.detail.get("assessed", True))
    tpm20 = bool(tpm and tpm.detail.get("tpm20"))
    drtm_running = bool(dg and dg.detail.get("drtm_running"))
    drtm_configured = bool(dg and dg.detail.get("drtm_configured"))
    hvci_running = bool(drv and drv.detail.get("hvci_running"))

    clean_reachable = tpm20 and drtm_running
    if clean_reachable:
        verdict = Verdict.CLEAN_ABOVE_SMM
        scope = ("DRTM quote can attest the launch chain ABOVE SMM. Unconditional CLEAN "
                 "still requires validated SMM locks + a clean external SPI dump (R1).")
    else:
        verdict = Verdict.CANNOT_VERIFY
        # DRTM-not-running gates CLEAN regardless of TPM, so the ceiling is firm even
        # when TPM couldn't be read -- but the scope text must not assert facts we lack.
        if not tpm_assessed:
            scope = ("TPM state undetermined (re-run elevated). DRTM/Secure Launch is not active "
                     "either way, so there is no software CLEAN path; external SPI read is the route to CLEAN.")
        elif tpm20 and drtm_configured:
            scope = "DRTM present but not running; enabling Secure Launch would raise the ceiling to CLEAN(Above-SMM)."
        elif tpm20:
            scope = "TPM 2.0 present but no active DRTM; no software CLEAN path. External SPI read is the only route to CLEAN."
        else:
            scope = "No TPM 2.0 / no DRTM; no software CLEAN path. External SPI read is the only route to CLEAN."

    # collect susceptibility findings that are actionable exposure signals
    flags: List[str] = []
    for e in evs:
        if e.verdict == Verdict.ANOMALOUS:
            flags.append(f"[{e.probe}] {e.finding}")

    escalations: List[str] = []
    if not clean_reachable:
        escalations.append("External SPI read (Tigard/Pico + flashrom, powered-off) -> earns CLEAN for flash contents.")
        if drtm_configured:
            escalations.append("Enable System Guard Secure Launch (DRTM) in firmware + Windows to unlock the quote path.")
    if hvci_running:
        escalations.append("HVCI is ON: susceptibility layer needs a non-driver path or an offline/WinPE scan.")

    return Ceiling(verdict=verdict, scope=scope, clean_reachable=clean_reachable,
                   drtm_running=drtm_running, tpm20=tpm20, hvci_running=hvci_running,
                   susceptibility_flags=flags, escalations=escalations)
