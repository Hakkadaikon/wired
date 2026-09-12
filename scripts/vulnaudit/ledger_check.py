#!/usr/bin/env python3
"""Check docs/security/vuln-ledger.md rows and print per-section counts.

Rules: a `[x]` row needs `verdict: fixed|already-safe` with `test:` and
`commit:` filled, or `verdict: n/a` with a reason after `test:`. Exits 1 on
any violation or duplicate id. Usage: ledger_check.py <ledger.md>
"""
import re
import sys
from collections import defaultdict

ROW = re.compile(r"^- \[([ ~x])\] (V-\d{4}) ")
FIELD = re.compile(r"(ours|verdict|test|commit|perf): ([^—]*)")


def parse(lines):
    rows, cur, section = [], None, "(none)"
    for ln in lines:
        if ln.startswith("## "):
            section = ln[3:].strip()
            continue
        m = ROW.match(ln)
        if m:
            cur = {"state": m.group(1), "id": m.group(2), "section": section, "text": ln}
            rows.append(cur)
        elif cur and ln.startswith("      "):
            cur["text"] += " " + ln.strip()
    return rows


def fields(row):
    return {k: v.strip() for k, v in FIELD.findall(row["text"])}


def violations(row):
    f = fields(row)
    v, test, commit = f.get("verdict", ""), f.get("test", ""), f.get("commit", "")
    if row["state"] != "x":
        return []
    if v in ("fixed", "already-safe") and test and commit:
        return []
    if v == "n/a" and test:
        return []
    return [f"{row['id']}: [x] without a complete verdict/test/commit ({v!r}, {test!r}, {commit!r})"]


def main(path):
    rows = parse(open(path, encoding="utf-8").read().splitlines())
    bad, seen, counts = [], set(), defaultdict(lambda: [0, 0, 0])
    for r in rows:
        if r["id"] in seen:
            bad.append(f"duplicate id {r['id']}")
        seen.add(r["id"])
        bad += violations(r)
        counts[r["section"]][" ~x".index(r["state"])] += 1
    for sec, (o, t, d) in counts.items():
        print(f"{sec}: open={o} triaged={t} done={d}")
    total = sum(sum(c) for c in counts.values())
    done = sum(c[2] for c in counts.values())
    print(f"TOTAL {total} rows, {done} done")
    for b in bad:
        print("ERROR", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/security/vuln-ledger.md"))
