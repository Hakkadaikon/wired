"""Shared row format of docs/security/vuln-ledger.md: one Markdown table row
per entry, under a `## <section>` heading. ledger_check.py, merge.py and
apply_triage.py all read/write rows through parse_row/format_row.
"""
import re

COLUMNS = ["ID", "Status", "Source", "Target", "Class", "Summary", "Verdict",
           "Layer", "Our code", "Test", "Commit", "Rationale"]
KEYS = ["id", "status", "source", "target", "class", "summary", "verdict",
        "layer", "ours", "test", "commit", "why"]
STATUS = {" ": "open", "~": "triaged", "x": "done"}

_SPLIT = re.compile(r"(?<!\\)\|")


def header():
    return ("| " + " | ".join(COLUMNS) + " |\n"
            "|" + "|".join("---" for _ in COLUMNS) + "|")


def _cell(v):
    return (v or "").replace("|", "\\|").replace("\n", " ").strip()


def format_row(d):
    return "| " + " | ".join(_cell(d.get(k, "")) for k in KEYS) + " |"


def parse_row(line):
    """The dict for one `| V-nnnn | ...` table row, or None."""
    if not line.startswith("| V-"):
        return None
    cells = [c.strip().replace("\\|", "|") for c in _SPLIT.split(line.strip())[1:-1]]
    if len(cells) != len(KEYS):
        return None
    return dict(zip(KEYS, cells))


def parse(lines):
    """Every entry row, each tagged with its `## ` section."""
    rows, section = [], "(none)"
    for ln in lines:
        if ln.startswith("## "):
            section = ln[3:].strip()
            continue
        d = parse_row(ln)
        if d:
            d["section"] = section
            rows.append(d)
    return rows
