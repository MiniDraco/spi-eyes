"""Vendor firmware-wrapper unwrapping (optional) -- wrap, don't reinvent.

Some vendors wrap the UEFI BIOS in a proprietary container our carver can't see
through (Dell PFS, AMI PFAT/UCP, Insyde). Rather than re-derive these gnarly,
multi-variant formats, we drive platomav's `biosutilities` if it's installed to peel
the wrapper down to the inner BIOS region, then carve that normally.

`biosutilities` is an OPTIONAL dependency: if it isn't installed, `unwrap()` returns
None and callers fall back to a whole-image blob reference. Install with:
    pip install biosutilities
"""
from __future__ import annotations

import contextlib
import glob
import io
import os
import shutil
import tempfile
from typing import List, Optional

# Discover whichever biosutilities extractors are available (graceful per-extractor).
_EXTRACTORS: List = []
for _mod, _cls in [("dell_pfs_extract", "DellPfsExtract"),
                   ("ami_pfat_extract", "AmiPfatExtract"),
                   ("ami_ucp_extract", "AmiUcpExtract"),
                   ("insyde_ifd_extract", "InsydeIfdExtract")]:
    try:
        _m = __import__(f"biosutilities.{_mod}", fromlist=[_cls])
        _EXTRACTORS.append(getattr(_m, _cls))
    except Exception:  # noqa: BLE001
        pass
_HAVE = len(_EXTRACTORS) > 0


def available() -> bool:
    return _HAVE


def _largest_fv_file(root: str) -> Optional[bytes]:
    best = None
    for f in glob.glob(os.path.join(root, "**", "*"), recursive=True):
        if not os.path.isfile(f):
            continue
        try:
            with open(f, "rb") as fh:
                b = fh.read()
        except OSError:
            continue
        if b"_FVH" in b and (best is None or len(b) > len(best)):
            best = b
    return best


def unwrap(data: bytes) -> Optional[bytes]:
    """Peel a vendor wrapper to the inner UEFI BIOS region (bytes), or None."""
    if not _HAVE:
        return None
    for Ex in _EXTRACTORS:
        outd = tempfile.mkdtemp()
        try:
            with contextlib.redirect_stdout(io.StringIO()):  # biosutilities is chatty
                e = Ex(input_object=data, extract_path=outd)
                if e.check_format():
                    e.parse_format()
                else:
                    continue
            got = _largest_fv_file(outd)
            if got:
                return got
        except Exception:  # noqa: BLE001  (a wrapper mismatch must never crash ingest)
            pass
        finally:
            shutil.rmtree(outd, ignore_errors=True)
    return None
