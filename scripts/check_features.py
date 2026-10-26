"""Check the requirement ledgers in docs/features/ (format: docs/features/FORMAT.md).

Usage: check_features.py [--fix]

Per ledger: every `- test:` line parses and names an existing file that
contains the cited function, every `[x]` item has a test line, no item ID
is used twice, and the Coverage line matches the boxes. The README rows and
the Total line must match the ledgers. --fix rewrites the Coverage, row and
Total lines from the boxes instead of reporting them.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FEAT = ROOT / "docs" / "features"
TEST_RE = re.compile(r"- test: `([^`]+)`\s+—\s+`([^`]+)`")
TEST_HEAD = re.compile(r"^\s*- test:.*$", re.M)
# boxes under these headings are tracked but not counted (README)
CUT = re.compile(r"^## (?:Not implemented|Out of scope|Experimental|Informational)", re.M)
BOX = re.compile(r"^- \[([x~ ])\] (\S+)", re.M)
X_BLOCK = re.compile(r"^- \[x\] (\S+).*\n((?:  .*\n)*)", re.M)
COV = re.compile(r"\*\*Coverage: \d+/\d+ tested, \d+ indirect, \d+ untested\.\*\*")
ROW = re.compile(
    r"^(\| \[[^\]]+\]\(([\w.-]+\.md)\) \| )\d+/\d+ \| \d+ \| \d+ \| \d+ \|", re.M
)
TOTAL = re.compile(r"\*\*Total: \d+/\d+ requirements demonstrated .*?untested\.\*\*", re.S)
PLACEHOLDER = re.compile(r"-X+$")


def join_wrapped(text):
    """Join a test line whose function name wrapped onto the next line."""
    return re.sub(r"—\s*\n\s+`", "— `", text)


def ref_error(ref_file, func):
    path = ROOT / ref_file
    if not path.is_file():
        return f"MISSING FILE {ref_file}"
    body = path.read_text(errors="replace")
    if re.search(rf"\b{re.escape(func)}\b", body) is None:
        return f"FUNC NOT IN FILE {ref_file} — {func}"
    return None


def ref_errors(joined):
    errs = [ref_error(f, fn) for f, fn in TEST_RE.findall(joined)]
    return [e for e in errs if e]


def malformed(joined):
    heads = TEST_HEAD.findall(joined)
    return [f"MALFORMED test line: {h.strip()[:80]}" for h in heads if not TEST_RE.search(h)]


def untested_x(joined):
    blocks = X_BLOCK.finditer(joined)
    return [f"[x] {m.group(1)} has no test line" for m in blocks if "- test:" not in m.group(2)]


def dup_ids(text):
    ids = [i for _, i in BOX.findall(text) if not PLACEHOLDER.search(i)]
    seen = set()
    dups = sorted({i for i in ids if i in seen or seen.add(i)})
    return [f"ID used twice: {i}" for i in dups]


def counts(text):
    boxes = [m for m, _ in BOX.findall(CUT.split(text)[0])]
    return boxes.count("x"), boxes.count("~"), boxes.count(" ")


def cov_line(n):
    x, t, u = n
    return f"**Coverage: {x}/{x + t + u} tested, {t} indirect, {u} untested.**"


def sync_cov(path, text, n, fix):
    want = cov_line(n)
    m = COV.search(text)
    if m is None:
        return ["Coverage line missing"]
    if m.group(0) == want:
        return []
    if fix:
        path.write_text(text.replace(m.group(0), want, 1))
        print(f"{path.name}: fixed -> {want}")
        return []
    return [f"{m.group(0)} != {want}"]


def check_ledger(path, fix):
    text = path.read_text()
    joined = join_wrapped(text)
    n = counts(text)
    errs = ref_errors(joined) + malformed(joined) + untested_x(joined)
    errs += dup_ids(text) + sync_cov(path, text, n, fix)
    return [f"{path.name}: {e}" for e in errs], n


def is_ledger(path):
    return path.name != "README.md" and COV.search(path.read_text()) is not None


def total_line(tot):
    x, t, u = tot
    pct = 100 * (x + t) / (x + t + u)
    return (
        f"**Total: {x + t}/{x + t + u} requirements demonstrated ({pct:.1f}%)"
        f" — {x} directly tested,\n{t} indirect, {u} untested.**"
    )


def readme_text(readme, ledgers):
    tot = [0, 0, 0]

    def row(m):
        x, t, u = ledgers[m.group(2)]
        tot[0], tot[1], tot[2] = tot[0] + x, tot[1] + t, tot[2] + u
        return f"{m.group(1)}{x + t}/{x + t + u} | {x} | {t} | {u} |"

    out = ROW.sub(row, readme)
    return TOTAL.sub(total_line(tot), out)


def sync_readme(ledgers, fix):
    path = FEAT / "README.md"
    readme = path.read_text()
    missing = [n for n in ROW.findall(readme) if n[1] not in ledgers]
    if missing:
        return [f"README.md: row for unknown ledger {m[1]}" for m in missing]
    want = readme_text(readme, ledgers)
    if want == readme:
        return []
    if fix:
        path.write_text(want)
        print("README.md: rows/total fixed")
        return []
    return ["README.md: rows or Total line do not match the ledgers (run --fix)"]


def main(argv):
    fix = "--fix" in argv
    errs, ledgers = [], {}
    for path in sorted(p for p in FEAT.glob("*.md") if is_ledger(p)):
        e, ledgers[path.name] = check_ledger(path, fix)
        errs += e
    errs += sync_readme(ledgers, fix)
    print("\n".join(errs + [f"{'FAIL' if errs else 'OK'} {len(errs)}"]))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
