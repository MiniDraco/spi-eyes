"""Windows introspection helpers.

The capability probe is READ-ONLY and loads NO kernel driver. It reaches state
only through native Windows surfaces (WMI/CIM, Secure Boot cmdlets, registry,
measured-boot logs) plus optional userland tools (smartctl) if present. Every
one of these is OS-mediated and therefore spoofable by a resident ring-0/-2/-3
implant -> callers must mark such Evidence `blindable=True`.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Optional, Tuple

_PS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def run_ps(script: str, timeout: int = 45) -> Tuple[bool, str, str]:
    """Run a PowerShell snippet. Returns (ok, stdout, stderr)."""
    try:
        p = subprocess.run(_PS + [script], capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return False, "", f"{type(e).__name__}: {e}"
    out = (p.stdout or "").lstrip("﻿").strip()
    err = (p.stderr or "").strip()
    if p.returncode != 0 and not out:
        return False, "", err or f"exit code {p.returncode}"
    return True, out, err


def run_ps_json(script: str, timeout: int = 45) -> Tuple[bool, Any, str]:
    """Run PowerShell whose output should be JSON. Returns (ok, parsed, err).

    Append your own `| ConvertTo-Json` in the script. Scalars (e.g. 'True') come
    back as the raw string when they are not valid JSON.
    """
    ok, out, err = run_ps(script, timeout)
    if not ok:
        return False, None, err
    if not out:
        return True, None, err
    try:
        return True, json.loads(out), err
    except json.JSONDecodeError:
        return True, out, err


def have(exe: str) -> bool:
    return shutil.which(exe) is not None


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def as_list(v: Any) -> list:
    """CIM array properties collapse to a scalar when single-valued; normalize."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]
