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


def row(m, where):
    h, mi = m["halstead"], m["mi"]
    return "%8.0f %6.1f %10.0f %6.2f %8.1f %7.1f %6.1f %5.0f %4.0f  %s" % (
        h["volume"], h["difficulty"], h["effort"], h["bugs"],
        mi["mi_original"], mi["mi_sei"], mi["mi_visual_studio"],
        m["nexits"]["sum"], m["nargs"]["total_functions"], where)


def functions(space):
    for s in space["spaces"]:
        if s["kind"] == "function":
            yield s
        yield from functions(s)


def breaks(m, limits):
    return ["%s %.2f" % (label, m[a][b])
            for a, b, label, bad in limits if bad(m[a][b])]


def load(root):
    units = []
    for d, _, names in os.walk(root):
        for n in names:
            with open(os.path.join(d, n)) as f:
                units.append(json.load(f))
    return sorted(units, key=lambda u: u["name"])


def check(units):
    n = 0
    for u in units:
        if u["name"] in EXEMPT:
            continue
        for s in functions(u):
            for b in breaks(s["metrics"], FN_LIMITS):
                print("%s:%d: warning: %s has %s" %
                      (u["name"], s["start_line"], s["name"], b))
                n += 1
        for b in breaks(u["metrics"], FILE_LIMITS):
            print("%s:1: warning: file has %s" % (u["name"], b))
            n += 1
    return n


def report(units):
    print("per function\n" + COLS)
    for u in units:
        for s in functions(u):
            print(row(s["metrics"], "%s@%d@%s" %
                      (s["name"], s["start_line"], u["name"])))
    print("\nper file\n" + COLS)
    for u in units:
        print(row(u["metrics"], u["name"]))


if sys.argv[1] == "--check":
    sys.exit(1 if check(load(sys.argv[2])) else 0)
report(load(sys.argv[1]))
