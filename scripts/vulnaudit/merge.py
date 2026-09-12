#!/usr/bin/env python3
"""Merge tasks/vuln/raw/*.json into tasks/vuln/catalog.json and print ledger
rows for every catalog entry not yet present in docs/security/vuln-ledger.md.

Usage: merge.py [--ledger docs/security/vuln-ledger.md] [--raw tasks/vuln/raw]
The rows are printed grouped by ledger section; paste them under the matching
heading (ids are assigned in catalog order, continuing after the ledger's
highest V-number). Dedup key: CVE/GHSA id, else spec section id.
"""
import glob
import json
import os
import re
import sys

AREA_TO_SECTION = {
    "quic-transport": "QUIC transport",
    "tls": "TLS 1.3",
    "crypto-symmetric": "Symmetric crypto and hashing",
    "crypto-asymmetric": "Public-key signatures and key agreement",
    "pki": "X.509 / DER / PKI",
    "http3": "HTTP/3, QPACK, HTTP Datagrams",
    "qpack": "HTTP/3, QPACK, HTTP Datagrams",
    "datagram": "HTTP/3, QPACK, HTTP Datagrams",
    "webtransport": "WebTransport",
    "moqt": "MoQT",
    "io": "IP / UDP / AF_XDP I/O",
    "media": "Media (mp4frag)",
    "deps": "Samples and dependencies",
}


def load_raw(raw_dir):
    recs = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
        try:
            doc = json.load(open(path, encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"skip {path}: {e}", file=sys.stderr)
            continue
        for r in doc.get("records", []):
            r = dict(r)
            r["_source_file"] = os.path.basename(path)
            recs.append(r)
    return recs


def key_of(r):
    return r.get("id") or ""


def dedup(recs):
    seen, out = {}, []
    for r in recs:
        k = key_of(r)
        aliases = set(r.get("aliases") or [])
        hit = seen.get(k) or next((seen[a] for a in aliases if a in seen), None)
        if hit:
            hit.setdefault("aliases", [])
            hit["aliases"] = sorted(set(hit["aliases"]) | aliases | {k})
            continue
        seen[k] = r
        for a in aliases:
            seen[a] = r
        out.append(r)
    return out


def ledger_ids(ledger_path):
    text = open(ledger_path, encoding="utf-8").read() if os.path.exists(ledger_path) else ""
    known = set(re.findall(r"\b(CVE-\d{4}-\d+|GHSA-[\w-]+|S-[\w.\-]+|L-\d+)\b", text))
    nums = [int(n) for n in re.findall(r"\bV-(\d{4})\b", text)]
    return known, (max(nums) if nums else 0)


def summary_of(r):
    if r["id"].startswith("S-"):
        return f"{r.get('title') or r.get('attack','')[:70]}: {r.get('defense','')[:90]}"
    return f"{r.get('bug_class','?')}: {(r.get('summary') or '')[:110]}"


def row(vnum, r):
    origin = r.get("product") or r.get("spec") or r.get("title", "")[:30]
    return (f"- [ ] V-{vnum:04d} {r['id']} ({origin}) {summary_of(r)}\n"
            f"      ours: {r.get('component_hint') or r.get('bug_class') or '?'} — verdict: ? — test: — commit: — perf: —")


def main(argv):
    ledger = "docs/security/vuln-ledger.md"
    raw = "tasks/vuln/raw"
    if "--ledger" in argv:
        ledger = argv[argv.index("--ledger") + 1]
    if "--raw" in argv:
        raw = argv[argv.index("--raw") + 1]
    recs = dedup(load_raw(raw))
    os.makedirs("tasks/vuln", exist_ok=True)
    json.dump({"count": len(recs), "records": recs}, open("tasks/vuln/catalog.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    known, vmax = ledger_ids(ledger)
    by_section = {}
    for r in recs:
        if r["id"] in known:
            continue
        by_section.setdefault(AREA_TO_SECTION.get(r.get("area"), "Unmapped area"), []).append(r)
    n = vmax
    for sec, rs in by_section.items():
        print(f"\n## {sec}  ({len(rs)} new)")
        for r in rs:
            n += 1
            print(row(n, r))
    print(f"\ncatalog: {len(recs)} records; new rows: {n - vmax}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
