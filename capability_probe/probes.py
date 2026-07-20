"""Platform dispatch for the evidence probes.

SPI-Eyes aims for ubiquity (Windows / Linux / macOS, x86-64 / ARM). Each OS has its
own SKU module with the evidence sources that platform actually exposes; this file
selects the right one at runtime. See PLATFORMS.md for the full SKU matrix.
"""
from __future__ import annotations

import platform
from typing import List

from .model import Evidence, Layer, Verdict


def _sku() -> str:
    sysname = platform.system()
    mach = (platform.machine() or "").lower()
    arch = "arm64" if mach in ("arm64", "aarch64") else ("x86-64" if mach in ("amd64", "x86_64") else mach or "?")
    return f"{sysname}/{arch}"


def run_all() -> List[Evidence]:
    sysname = platform.system()
    if sysname == "Windows":
        from . import probes_windows as mod
    elif sysname == "Linux":
        from . import probes_linux as mod
    elif sysname == "Darwin":
        from . import probes_macos as mod
    else:
        return [Evidence("platform", Layer.CAPABILITY,
                         f"unsupported platform '{sysname}' -- no SKU (see PLATFORMS.md)",
                         Verdict.NOT_ASSESSED, Verdict.CANNOT_VERIFY, True, "n/a")]
    return mod.run()


def sku_label() -> str:
    return _sku()
