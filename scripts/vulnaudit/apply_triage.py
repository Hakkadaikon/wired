#!/usr/bin/env python3
"""Apply triage JSON files to the ledger.

Each tasks/vuln/triage/*.json is {"rows": [{"vid": "V-0001", "verdict": "needs-fix|already-safe|n/a",
"ours": "src/...", "reason": "...", "layer": "unit|fuzz|tla|lean", "test": "<planned or existing test name>",
"existing_test": true|false, "priority": "P1|P2|P3"}]}.
A row becomes `triaged` with its fields filled; `already-safe` with existing_test=true or `n/a` become `done`
(commit: `existing`). Usage: apply_triage.py [ledger] [triage dir]
"""
import glob
import json
import sys

from ledger_table import format_row, parse_row


def load_triage(tdir):
    triage = {}
    for f in sorted(glob.glob(f"{tdir}/*.json")):
        for r in json.load(open(f, encoding="utf-8"))["rows"]:
            triage[r["vid"]] = r
    return triage


def _closed(t):
    v = t["verdict"]
    return (v == "already-safe" and t.get("existing_test")) or v == "n/a"


def _test(t):
    return "" if t["verdict"] == "n/a" else t.get("test") or ""


def _commit(t, closed):
    return "existing" if closed and t["verdict"] != "n/a" else ""


def _why(t):
    return t.get("reason", "") or ("n/a" if t["verdict"] == "n/a" else "")


def fields(t):
    """The ledger columns a triage row fills in."""
    closed = _closed(t)
    return {
        "status": {True: "done", False: "triaged"}[bool(closed)],
        "verdict": t["verdict"],
        "ours": t.get("ours", "?"),
        "test": _test(t),
        "commit": _commit(t, closed),
        "layer": f"{t.get('layer', '')} {t.get('priority', '')}".strip(),
        "why": _why(t),
    }


def _pending(d, triage):
    return d and d["id"] in triage and d["status"] != "done"


def apply(ln, triage):
    """(the ledger line with its triage applied, 1) or (ln, 0) if none applies."""
    d = parse_row(ln)
    if not _pending(d, triage):
        return ln, 0
    d.update(fields(triage[d["id"]]))
    return format_row(d), 1


def main(ledger="docs/security/vuln-ledger.md", tdir="tasks/vuln/triage"):
    triage = load_triage(tdir)
    out, applied = [], 0
    for ln in open(ledger, encoding="utf-8").read().splitlines():
        ln, n = apply(ln, triage)
        out.append(ln)
        applied += n
    open(ledger, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"applied {applied} triage rows")


if __name__ == "__main__":
    main(*sys.argv[1:])
