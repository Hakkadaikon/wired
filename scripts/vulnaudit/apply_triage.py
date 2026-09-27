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


def main(ledger="docs/security/vuln-ledger.md", tdir="tasks/vuln/triage"):
    triage = {}
    for f in sorted(glob.glob(f"{tdir}/*.json")):
        for r in json.load(open(f, encoding="utf-8"))["rows"]:
            triage[r["vid"]] = r
    out, applied = [], 0
    for ln in open(ledger, encoding="utf-8").read().splitlines():
        d = parse_row(ln)
        if d and d["id"] in triage and d["status"] != "done":
            t = triage[d["id"]]
            v = t["verdict"]
            closed = (v == "already-safe" and t.get("existing_test")) or v == "n/a"
            d.update({
                "status": "done" if closed else "triaged",
                "verdict": v,
                "ours": t.get("ours", "?"),
                "test": "" if v == "n/a" else t.get("test") or "",
                "commit": "existing" if closed and v != "n/a" else "",
                "layer": f"{t.get('layer', '')} {t.get('priority', '')}".strip(),
                "why": t.get("reason", "") or ("n/a" if v == "n/a" else ""),
            })
            ln = format_row(d)
            applied += 1
        out.append(ln)
    open(ledger, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"applied {applied} triage rows")


if __name__ == "__main__":
    main(*sys.argv[1:])
