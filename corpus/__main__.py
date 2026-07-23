"""Build/match firmware reference manifests and manage the version-aware corpus.

  python -m corpus build  <image.fd> [--out ref.json --vendor V --model M
                                      --version X --tier vendor-signed]
  python -m corpus match  <image.fd> <ref.json>
  python -m corpus ingest <url> --vendor V --model M --version X [--tier T]
  python -m corpus lookup --vendor V --model M --version X
  python -m corpus check  <image.fd> --vendor V --model M --version X
  python -m corpus list
"""
from __future__ import annotations

import argparse
import sys

from .index import CorpusIndex
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


def cmd_ingest(a) -> int:
    from .ingest import ingest
    r = ingest(a.url, vendor=a.vendor, model=a.model, version=a.version, tier=a.tier)
    if not r.get("ok"):
        print(f"ingest FAILED: {r.get('error')}  ({a.url})")
        return 1
    print(f"ingested {a.vendor} {a.model} {a.version}: {r['code_modules']} code modules "
          f"(from {r['member']}, {r['image_bytes']//1024//1024}MB image)")
    print(f"  -> {r['path']}")
    return 0


def cmd_lookup(a) -> int:
    idx = CorpusIndex()
    e = idx.lookup(a.vendor, a.model, a.version)
    if e:
        print(f"COVERED: {e.vendor} {e.model} {e.version} [{e.tier}] "
              f"{e.code_modules} modules -> {e.path}")
        return 0
    have = idx.versions_for(a.vendor, a.model)
    print(f"NOT COVERED: {a.vendor} {a.model} {a.version}")
    print(f"  versions we have for this model: {have or '(none)'}")
    print("  -> verdict CANNOT-VERIFY; user can submit this version's hash manifest.")
    return 0


def cmd_check(a) -> int:
    idx = CorpusIndex()
    e = idx.lookup(a.vendor, a.model, a.version)
    if not e:
        print(f"no reference for EXACT version {a.vendor} {a.model} {a.version} "
              f"(have: {idx.versions_for(a.vendor, a.model) or 'none'})")
        print("verdict: CANNOT-VERIFY (never matched against a different version).")
        return 0
    cr = _carve_file(a.image)
    r = match(cr, load_manifest(e.path))
    print(f"checked against {e.version} [{e.tier}]: matched={r.matched}/{r.code_total_ref} "
          f"mismatch={len(r.mismatched)} missing={len(r.missing)} extra={len(r.extra)} "
          f"-> {r.content_verdict}")
    return 0


def cmd_list(a) -> int:
    idx = CorpusIndex()
    cov = idx.coverage()
    print(f"corpus: {cov['entries']} entries, {cov['models']} models, {cov['vendors']} vendors")
    for e in idx.all_entries():
        what = (f"{e.code_modules} modules" if e.kind == "modules"
                else f"blob [{e.component or 'chip fw'}]")
        print(f"  {e.vendor} / {e.model} / {e.version} [{e.tier}] {what}")
    return 0


def cmd_validate(a) -> int:
    from .manifest import load_manifest, validate_manifest
    ok, issues = validate_manifest(load_manifest(a.manifest))
    if ok:
        print(f"VALID: {a.manifest} is a well-formed, hash-only reference. Safe to submit.")
        return 0
    print(f"INVALID: {a.manifest}")
    for i in issues:
        print(f"  - {i}")
    return 1


def cmd_lvfs(a) -> int:
    from .lvfs import ingest_lvfs
    def _pr(r):
        if r.get("ok"):
            what = (f"{r['code_modules']} modules" if r.get("kind") == "modules"
                    else f"blob {r.get('image_kb', '?')}KB [{r.get('category', '')}]")
            print(f"  + {r['vendor']} {r['model']} {r['version']}: {what}")
        else:
            print(f"  - {r['vendor']} {r['model']} {r['version']}: skip ({r['error']})")
    res = ingest_lvfs(limit=a.limit, max_attempts=a.max_attempts, tier="vendor-signed", on_result=_pr)
    ok = sum(1 for r in res if r.get("ok"))
    print(f"\nLVFS ingest: {ok} references minted, {len(res)-ok} skipped (vendor wrappers / non-UEFI)")
    return 0


def cmd_corroborate(a) -> int:
    from .corroborate import corroborate
    srcs = []
    for p in a.images:
        with open(p, "rb") as fh:
            srcs.append((p, fh.read()))
    r = corroborate(srcs, vendor=a.vendor, model=a.model, version=a.version)
    print(f"corroboration across {len(r.sources)} sources: {r.module_count} code modules")
    if r.error:
        print(f"  error: {r.error}")
        return 1
    if r.agree:
        print("  AGREE -> all sources produced identical per-module hashes.")
        print("  tier: multi-source-corroborated (stronger than single-source; NOT clean-capable")
        print("        unless one source is authoritative -- N sources may share a tainted origin).")
        if a.out and r.manifest:
            from .manifest import save_manifest
            save_manifest(r.manifest, a.out)
            print(f"  -> {a.out}")
    else:
        print(f"  DISAGREE -> {len(r.disagreements)} module(s) differ across sources.")
        print("  At least one source is tampered or corrupt. DO NOT ingest; investigate:")
        for d in r.disagreements[:8]:
            print(f"    ! {d['guid']}: {d['per_source']}")
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
    ing = sub.add_parser("ingest", help="download an update URL -> versioned reference")
    ing.add_argument("url")
    ing.add_argument("--vendor", required=True)
    ing.add_argument("--model", required=True)
    ing.add_argument("--version", required=True)
    ing.add_argument("--tier", default="vendor-signed")
    ing.set_defaults(func=cmd_ingest)
    lk = sub.add_parser("lookup", help="is (vendor,model,version) covered?")
    for f in ("vendor", "model", "version"):
        lk.add_argument("--" + f, required=True)
    lk.set_defaults(func=cmd_lookup)
    ck = sub.add_parser("check", help="version-aware: lookup ref by version, then line-check")
    ck.add_argument("image")
    for f in ("vendor", "model", "version"):
        ck.add_argument("--" + f, required=True)
    ck.set_defaults(func=cmd_check)
    ls = sub.add_parser("list", help="show corpus coverage")
    ls.set_defaults(func=cmd_list)
    va = sub.add_parser("validate", help="check a submission is well-formed + hash-only")
    va.add_argument("manifest")
    va.set_defaults(func=cmd_validate)
    lv = sub.add_parser("lvfs", help="bulk-ingest vendor-signed references from LVFS")
    lv.add_argument("--limit", type=int, default=8, help="stop after N successful references")
    lv.add_argument("--max-attempts", dest="max_attempts", type=int, default=20)
    lv.set_defaults(func=cmd_lvfs)
    co = sub.add_parser("corroborate", help="cross-check the same version from >=2 sources")
    co.add_argument("images", nargs="+", help="the same (vendor,model,version) image from N sources")
    for f in ("vendor", "model", "version"):
        co.add_argument("--" + f, required=True)
    co.add_argument("--out", help="write a corroborated manifest if sources agree")
    co.set_defaults(func=cmd_corroborate)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
