#!/usr/bin/env python3
"""Apply triage JSON files to the ledger.

Each tasks/vuln/triage/*.json is {"rows": [{"vid": "V-0001", "verdict": "needs-fix|already-safe|n/a",
"ours": "src/...", "reason": "...", "layer": "unit|fuzz|tla|lean", "test": "<planned or existing test name>",
"existing_test": true|false, "priority": "P1|P2|P3"}]}.
A row becomes `[~]` with its fields filled; `already-safe` with existing_test=true or `n/a` become `[x]`
(commit: `existing`). Usage: apply_triage.py [ledger] [triage dir]
"""
import glob
import json
import re
import sys


def main(ledger="docs/security/vuln-ledger.md", tdir="tasks/vuln/triage"):
    triage = {}
    for f in sorted(glob.glob(f"{tdir}/*.json")):
        for r in json.load(open(f, encoding="utf-8"))["rows"]:
            triage[r["vid"]] = r
    out, cur, applied = [], None, 0
    for ln in open(ledger, encoding="utf-8").read().splitlines():
        m = re.match(r"^- \[([ ~x])\] (V-\d{4}) (.*)$", ln)
        if m and m.group(2) in triage and m.group(1) != "x":
            t = triage[m.group(2)]
            v = t["verdict"]
            closed = (v == "already-safe" and t.get("existing_test")) or v == "n/a"
            state = "x" if closed else "~"
            test = t.get("test") or ""
            if v == "n/a":
                test = t.get("reason", "") or "n/a"
            commit = "existing" if closed and v != "n/a" else ""
            cur = (state, t, test, commit)
            out.append(f"- [{state}] {m.group(2)} {m.group(3)}")
            applied += 1
            continue
        if cur and ln.startswith("      ours:"):
            state, t, test, commit = cur
            pr = t.get("priority", "")
            out.append(f"      ours: {t.get('ours','?')} — verdict: {t['verdict']} — test: {test} — commit: {commit} — perf: — layer: {t.get('layer','')} {pr} — why: {t.get('reason','')}")
            cur = None
            continue
        out.append(ln)
    open(ledger, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"applied {applied} triage rows")


if __name__ == "__main__":
    main(*sys.argv[1:])
