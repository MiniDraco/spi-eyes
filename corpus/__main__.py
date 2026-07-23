"""Mint a reference manifest from a firmware image, or line-check an image against one.

  python -m corpus build <image.fd> [--out ref.json] [--vendor V --model M
                                     --version X --url U --tier vendor-signed]
  python -m corpus match <image.fd> <ref.json>
"""
from __future__ import annotations

import argparse
import sys

from .manifest import build_manifest, load_manifest, match, save_manifest
from .uefifv import carve


def _carve_file(path: str):
    with open(path, "rb") as fh:
        data = fh.read()
    cr = carve(data)
    if not cr.ok:
        print(f"carve failed: {cr.error}")
        raise SystemExit(1)
    return cr


def cmd_build(a) -> int:
    cr = _carve_file(a.image)
    source = {"vendor": a.vendor, "model": a.model, "version": a.version,
              "url": a.url, "trust_tier": a.tier}
    m = build_manifest(cr, source={k: v for k, v in source.items() if v})
    out = a.out or (a.image + ".manifest.json")
    save_manifest(m, out)
    print(f"carved {len(cr.all_files)} files ({m['code_module_count']} code modules) "
          f"from {len(cr.fvs)} FVs")
    print(f"trust tier: {m['source'].get('trust_tier')}")
    print(f"manifest -> {out}")
    return 0


def cmd_match(a) -> int:
    cr = _carve_file(a.image)
    m = load_manifest(a.manifest)
    r = match(cr, m)
    print(f"line check vs reference (tier={r.trust_tier}, clean-capable={r.clean_capable_tier})")
    print(f"  code modules in reference : {r.code_total_ref}")
    print(f"  matched                   : {r.matched}")
    print(f"  MISMATCH (modified)       : {len(r.mismatched)}")
    print(f"  MISSING  (removed)        : {len(r.missing)}")
    print(f"  EXTRA    (added)          : {len(r.extra)}")
    for x in r.mismatched[:10]:
        print(f"    ! MISMATCH {x['guid']}  got {x['sha256'][:16]}..")
    for x in r.extra[:10]:
        print(f"    ! EXTRA    {x['guid']}  {x['type']}")
    for x in r.missing[:10]:
        print(f"    ! MISSING  {x['guid']}")
    print()
    if r.content_verdict == "CONTENT-MATCH":
        print("  CONTENT-MATCH: every code module matches the reference.")
        print("  -> earns CLEAN ONLY if (a) tier is clean-capable AND (b) the image came")
        print("     from a trustworthy read (external SPI / DRTM). A software dump = CANNOT-VERIFY.")
    else:
        print(f"  ANOMALOUS: {r.anomalies} code-module deviation(s) from the reference.")
    return 0


def main(argv) -> int:
    p = argparse.ArgumentParser(prog="corpus", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="mint a reference manifest from a trusted image")
    b.add_argument("image")
    b.add_argument("--out")
    b.add_argument("--vendor")
    b.add_argument("--model")
    b.add_argument("--version")
    b.add_argument("--url")
    b.add_argument("--tier", default="unverified")
    b.set_defaults(func=cmd_build)
    m = sub.add_parser("match", help="line-check an image against a reference manifest")
    m.add_argument("image")
    m.add_argument("manifest")
    m.set_defaults(func=cmd_match)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
