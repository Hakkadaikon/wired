#!/usr/bin/env python3
"""Tabulate rust-code-analysis JSON (one file per source, under argv[1]):
Halstead volume/difficulty/effort/bugs, the maintainability index (MI),
exit points and parameters per function, then per file. MI is printed in
its three forms: original (171-based), SEI (with comment weight) and
Visual Studio (0..100).

With --check, print only what breaks a limit below (compiler warning
format) and exit 1 if anything does."""
import json
import os
import sys

COLS = ("  volume   diff     effort   bugs  mi_orig  mi_sei  mi_vs exits args"
        "  location")

# Common guidelines: Halstead volume <= 1000 per function and <= 8000 per
# file, difficulty <= 30 (Verifysoft); delivered bugs <= 0.5 per function
# and <= 2 per file; MI original >= 65 (Oman/Hagemeister), Visual Studio
# >= 20; <= 4 exits; <= 7 parameters (SonarQube). MI is a per-function
# measure: file-level MI falls with file size alone (it would cap files at
# ~50 lines), so no file MI limit.
FN_LIMITS = (
    ("halstead", "volume", "volume", lambda v: v > 1000),
    ("halstead", "difficulty", "difficulty", lambda v: v > 30),
    ("halstead", "bugs", "bugs", lambda v: v > 0.5),
    ("mi", "mi_original", "MI", lambda v: v < 65),
    ("mi", "mi_visual_studio", "MI (VS)", lambda v: v < 20),
    ("nexits", "sum", "exits", lambda v: v > 4),
    ("nargs", "total_functions", "parameters", lambda v: v > 7),
)
FILE_LIMITS = (
    ("halstead", "volume", "volume", lambda v: v > 8000),
    ("halstead", "bugs", "bugs", lambda v: v > 2),
)
# Generated data, not code: its volume counts the table's literals.
EXEMPT = ("src/crypto/asymmetric/ecc/p256fixed/p256fixed_table.c",)


def cell(v, width, prec):
    """v right-aligned in width with prec decimals; '-' for null."""
    return "-".rjust(width) if v is None else "%*.*f" % (width, prec, v)


def row(m, where):
    h, mi = m["halstead"], m["mi"]
    cells = ((h["volume"], 8, 0), (h["difficulty"], 6, 1),
             (h["effort"], 10, 0), (h["bugs"], 6, 2),
             (mi["mi_original"], 8, 1), (mi["mi_sei"], 7, 1),
             (mi["mi_visual_studio"], 6, 1), (m["nexits"]["sum"], 5, 0),
             (m["nargs"]["total_functions"], 4, 0))
    return " ".join(cell(*c) for c in cells) + "  " + where


def functions(space):
    for s in space["spaces"]:
        if s["kind"] == "function":
            yield s
        yield from functions(s)


def broken(m, limit):
    """Whether m breaks limit. A null value (rust-code-analysis emits it
    for a function with no operands) has nothing to measure."""
    a, b, _, bad = limit
    return m[a][b] is not None and bad(m[a][b])


def breaks(m, limits):
    return ["%s %.2f" % (lim[2], m[lim[0]][lim[1]])
            for lim in limits if broken(m, lim)]


def load(root):
    units = []
    for d, _, names in os.walk(root):
        for n in names:
            with open(os.path.join(d, n)) as f:
                units.append(json.load(f))
    return sorted(units, key=lambda u: u["name"])


def fn_warnings(u):
    return ["%s:%d: warning: %s has %s" %
            (u["name"], s["start_line"], s["name"], b)
            for s in functions(u) for b in breaks(s["metrics"], FN_LIMITS)]


def file_warnings(u):
    return ["%s:1: warning: file has %s" % (u["name"], b)
            for b in breaks(u["metrics"], FILE_LIMITS)]


def checked(units):
    return [u for u in units if u["name"] not in EXEMPT]


def emit(lines):
    sys.stdout.writelines(line + "\n" for line in lines)


def check(units):
    """Print every limit broken (compiler warning format); their count."""
    lines = [w for u in checked(units)
             for w in fn_warnings(u) + file_warnings(u)]
    emit(lines)
    return len(lines)


def fn_rows(units):
    return [row(s["metrics"], "%s@%d@%s" %
                (s["name"], s["start_line"], u["name"]))
            for u in units for s in functions(u)]


def report(units):
    print("per function\n" + COLS)
    print("\n".join(fn_rows(units)))
    print("\nper file\n" + COLS)
    print("\n".join(row(u["metrics"], u["name"]) for u in units))


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        sys.exit(1 if check(load(sys.argv[2])) else 0)
    report(load(sys.argv[1]))
