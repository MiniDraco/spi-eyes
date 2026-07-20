"""Core data model for SPI-Eyes.

This is the spine described in WHITEPAPER.md §4-§6: every probe returns Evidence
carrying a `max_earnable_verdict` (its trust ceiling) and a `blindable` flag
(could a resident ring -2/-3 implant have faked this?). The aggregate verdict can
never exceed max(max_earnable_verdict) over contributing evidence  ->  V <= max(Mi).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    # Ordered weakest -> strongest for the *earnable clean-bill* axis.
    CANNOT_VERIFY = "CANNOT-VERIFY"        # fail-closed default
    CLEAN_ABOVE_SMM = "CLEAN(Above-SMM)"   # DRTM-earned; SMM domain excluded (R1)
    CLEAN = "CLEAN"                        # unconditional; needs SMM-locks + external dump
    # off the clean axis:
    ANOMALOUS = "ANOMALOUS"                # positive evidence of deviation
    NOT_ASSESSED = "NOT-ASSESSED"          # probe did not run (missing tool / needs admin)


# rank only for the clean-bill axis (higher == a stronger clean can be earned)
_CLEAN_RANK = {
    Verdict.CANNOT_VERIFY: 0,
    Verdict.CLEAN_ABOVE_SMM: 1,
    Verdict.CLEAN: 2,
}


def clean_rank(v: Verdict) -> int:
    return _CLEAN_RANK.get(v, 0)


class Layer(str, Enum):
    CAPABILITY = "CAPABILITY"          # what verdict can this machine ever earn?
    SUSCEPTIBILITY = "SUSCEPTIBILITY"  # are the vendor locks set? (exposure, not infection)
    INFECTION = "INFECTION"            # is something actually resident?


@dataclass
class Evidence:
    probe: str
    layer: Layer
    finding: str                       # one-line human summary
    verdict: Verdict                   # what this probe concluded right now
    max_earnable_verdict: Verdict      # the ceiling of this evidence source
    blindable: bool                    # could ring -2/-3 have faked this reading?
    trust: str                         # e.g. "OS-API (spoofable)" / "hardware-rooted"
    detail: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_json(self) -> dict:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["verdict"] = self.verdict.value
        d["max_earnable_verdict"] = self.max_earnable_verdict.value
        return d
