#!/usr/bin/env python3
"""Check docs/security/vuln-ledger.md rows and print per-section counts.

Rules: a `done` row needs Verdict `fixed|already-safe` with Test and Commit
filled, or Verdict `n/a` with a Rationale (rows: ledger_table.py). Exits 1 on
any violation or duplicate id. Usage: ledger_check.py <ledger.md>
"""
import re
import sys
from collections import defaultdict
from operator import itemgetter

from ledger_table import parse


def _has_test_commit(row):
    return bool(row["test"] and row["commit"])


def _has_why(row):
    return bool(row["why"])


def _never(row):
    return False


# verdict -> what a `done` row with that verdict must have filled
COMPLETE = {"fixed": _has_test_commit, "already-safe": _has_test_commit, "n/a": _has_why}


def violations(row):
    if row["status"] != "done" or COMPLETE.get(row["verdict"], _never)(row):
        return []
    return [f"{row['id']}: done without a complete verdict/test/commit "
            f"({row['verdict']!r}, {row['test']!r}, {row['commit']!r})"]


def known_tests(root="tests"):
    """Every test_* identifier defined in tests/**/*.c (a closed row may only
    cite one of these)."""
    import glob
    names = set()
    for f in glob.glob(f"{root}/**/*.c", recursive=True):
        names |= set(re.findall(r"\b(test_[A-Za-z0-9_]+)\s*\(", open(f, encoding="utf-8", errors="replace").read()))
    return names


def _cites_c_tests(row):
    return row["status"] == "done" and row["verdict"] in ("fixed", "already-safe")


def _missing(cited, names):
    return [t for t in cited if t not in names]


def test_missing(row, names):
    # a row citing no test_* (e.g. an audit output for deps rows) passes
    if not _cites_c_tests(row):
        return []
    missing = _missing(re.findall(r"\btest_[A-Za-z0-9_]+", row["test"]), names)
    return [f"{row['id']}: cited test not found in tests/: {', '.join(missing)}"] if missing else []


def _duplicate(r, seen):
    dup = [f"duplicate id {r['id']}"] if r["id"] in seen else []
    seen.add(r["id"])
    return dup


def check_rows(rows, names):
    bad, seen, counts = [], set(), defaultdict(lambda: [0, 0, 0])
    for r in rows:
        bad += _duplicate(r, seen) + violations(r) + test_missing(r, names)
        counts[r["section"]][("open", "triaged", "done").index(r["status"])] += 1
    return bad, counts


def print_counts(counts):
    for sec, (o, t, d) in counts.items():
        print(f"{sec}: open={o} triaged={t} done={d}")
    total = sum(map(sum, counts.values()))
    done = sum(map(itemgetter(2), counts.values()))
    print(f"TOTAL {total} rows, {done} done")


def main(path):
    rows = parse(open(path, encoding="utf-8").read().splitlines())
    bad, counts = check_rows(rows, known_tests())
    print_counts(counts)
    for b in bad:
        print("ERROR", b)
    return int(bool(bad))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/security/vuln-ledger.md"))
