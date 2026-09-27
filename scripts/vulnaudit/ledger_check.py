#!/usr/bin/env python3
"""Check docs/security/vuln-ledger.md rows and print per-section counts.

Rules: a `done` row needs Verdict `fixed|already-safe` with Test and Commit
filled, or Verdict `n/a` with a Rationale (rows: ledger_table.py). Exits 1 on
any violation or duplicate id. Usage: ledger_check.py <ledger.md>
"""
import re
import sys
from collections import defaultdict

from ledger_table import parse


def violations(row):
    v, test, commit, why = row["verdict"], row["test"], row["commit"], row["why"]
    if row["status"] != "done":
        return []
    if v in ("fixed", "already-safe") and test and commit:
        return []
    if v == "n/a" and why:
        return []
    return [f"{row['id']}: done without a complete verdict/test/commit ({v!r}, {test!r}, {commit!r})"]


def known_tests(root="tests"):
    """Every test_* identifier defined in tests/**/*.c (a closed row may only
    cite one of these)."""
    import glob
    names = set()
    for f in glob.glob(f"{root}/**/*.c", recursive=True):
        names |= set(re.findall(r"\b(test_[A-Za-z0-9_]+)\s*\(", open(f, encoding="utf-8", errors="replace").read()))
    return names


def test_missing(row, names):
    if row["status"] != "done" or row["verdict"] not in ("fixed", "already-safe"):
        return []
    cited = re.findall(r"\btest_[A-Za-z0-9_]+", row["test"])
    if not cited:
        return []  # a non-C evidence (e.g. an audit output) is allowed for deps rows
    missing = [t for t in cited if t not in names]
    return [f"{row['id']}: cited test not found in tests/: {', '.join(missing)}"] if missing else []


def main(path):
    rows = parse(open(path, encoding="utf-8").read().splitlines())
    bad, seen, counts = [], set(), defaultdict(lambda: [0, 0, 0])
    names = known_tests()
    for r in rows:
        if r["id"] in seen:
            bad.append(f"duplicate id {r['id']}")
        seen.add(r["id"])
        bad += violations(r)
        bad += test_missing(r, names)
        counts[r["section"]][("open", "triaged", "done").index(r["status"])] += 1
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
