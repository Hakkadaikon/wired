#!/usr/bin/env python3
"""Merge tasks/vuln/raw/*.json into tasks/vuln/catalog.json and print ledger
rows for every catalog entry not yet present in docs/security/vuln-ledger.md.

Usage: merge.py [--ledger docs/security/vuln-ledger.md] [--raw tasks/vuln/raw]
The table rows are printed grouped by ledger section; paste them at the end
of the matching section's table (ids are assigned in catalog order, continuing after the ledger's
highest V-number). Dedup key: CVE/GHSA id, else spec section id.
"""
import glob
import json
import os
import re
import sys
from itertools import chain

from ledger_table import format_row

AREA_TO_SECTION = {
    "quic-transport": "QUIC transport",
    "migration": "QUIC transport",
    "connection-id": "QUIC transport",
    "flow-control": "QUIC transport",
    "retry-token": "QUIC transport",
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


def _parts(recs):
    # a collector grouped records by part (a part may be null)
    return list(chain.from_iterable(filter(None, recs.values())))


def _records(path):
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"skip {path}: {e}", file=sys.stderr)
        return []
    recs = doc.get("records", [])
    return {dict: _parts}.get(type(recs), list)(recs)


def load_raw(raw_dir):
    recs = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
        for r in _records(path):
            recs.append(dict(r, _source_file=os.path.basename(path)))
    return recs


def key_of(r):
    return r.get("id") or ""


def _alias_hit(seen, aliases):
    return next((seen[a] for a in aliases if a in seen), None)


def _aliases(r):
    return set(r.get("aliases") or [])


def _hit(seen, k, aliases):
    return seen.get(k) or _alias_hit(seen, aliases)


def _absorb(hit, k, aliases):
    hit["aliases"] = sorted(set(hit.get("aliases", [])) | aliases | {k})


def dedup(recs):
    seen, out = {}, []
    for r in recs:
        k, aliases = key_of(r), _aliases(r)
        hit = _hit(seen, k, aliases)
        if hit:
            _absorb(hit, k, aliases)
            continue
        seen.update(dict.fromkeys([k, *aliases], r))
        out.append(r)
    return out


def _read(path):
    return open(path, encoding="utf-8").read() if os.path.exists(path) else ""


def ledger_ids(ledger_path):
    text = _read(ledger_path)
    known = set(re.findall(r"\b(CVE-\d{4}-\d+|GHSA-[\w-]+|S-[\w.\-]+|L-\d+)\b", text))
    return known, max(map(int, re.findall(r"\bV-(\d{4})\b", text)), default=0)


def _spec_class_and_summary(r):
    return r.get("title") or r.get("attack", "")[:70], (r.get("defense") or "")[:90]


def _cve_class_and_summary(r):
    return r.get("bug_class", "?"), (r.get("summary") or "")[:110]


def class_and_summary(r):
    spec = r["id"].startswith("S-")
    return {True: _spec_class_and_summary, False: _cve_class_and_summary}[spec](r)


def _target(r):
    return r.get("product") or r.get("spec") or r.get("title", "")[:30]


def _ours(r):
    return r.get("component_hint") or r.get("bug_class") or "?"


def row(vnum, r):
    cls, summary = class_and_summary(r)
    return format_row({
        "id": f"V-{vnum:04d}", "status": "open", "source": r["id"],
        "target": _target(r), "class": cls, "summary": summary, "verdict": "?",
        "ours": _ours(r)})


def _opt(argv, name, default):
    return argv[argv.index(name) + 1] if name in argv else default


def write_catalog(recs):
    os.makedirs("tasks/vuln", exist_ok=True)
    with open("tasks/vuln/catalog.json", "w", encoding="utf-8") as f:
        json.dump({"count": len(recs), "records": recs}, f, indent=1, ensure_ascii=False)


def new_by_section(recs, known):
    by_section = {}
    for r in recs:
        if r["id"] in known:
            continue
        by_section.setdefault(AREA_TO_SECTION.get(r.get("area"), "Unmapped area"), []).append(r)
    return by_section


def print_rows(by_section, n):
    """Print each section's new rows numbered after n; the last number used."""
    for sec, rs in by_section.items():
        print(f"\n## {sec}  ({len(rs)} new)")
        for r in rs:
            n += 1
            print(row(n, r))
    return n


def main(argv):
    ledger = _opt(argv, "--ledger", "docs/security/vuln-ledger.md")
    raw = _opt(argv, "--raw", "tasks/vuln/raw")
    recs = dedup(load_raw(raw))
    write_catalog(recs)
    known, vmax = ledger_ids(ledger)
    n = print_rows(new_by_section(recs, known), vmax)
    print(f"\ncatalog: {len(recs)} records; new rows: {n - vmax}", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
