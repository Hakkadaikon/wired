#!/usr/bin/env python3
"""Tabulate rust-code-analysis JSON (one file per source, under argv[1]):
Halstead volume/difficulty/effort/bugs, the maintainability index (MI),
exit points and parameters per function, then per file. MI is printed in
its three forms: original (171-based), SEI (with comment weight) and
Visual Studio (0..100).

With --check [--profile NAME], print only what breaks the profile's
limits (compiler warning format) and exit 1 if anything does.

The ratchet profiles' MI (VS) floors are the MI original floor * 100/171,
the Visual Studio scaling."""

import json
import os
import sys

COLS = "  volume   diff     effort   bugs  mi_orig  mi_sei  mi_vs exits args  location"


# Common guidelines: Halstead volume <= 1000 per function and <= 8000 per
# file, difficulty <= 30 (Verifysoft); delivered bugs <= 0.5 per function
# and <= 2 per file; MI original >= 65 (Oman/Hagemeister), Visual Studio
# >= 20; <= 4 exits; <= 7 parameters (SonarQube). MI is a per-function
# measure: file-level MI falls with file size alone (it would cap files at
# ~50 lines), so no file MI limit.
def over(x):
    return lambda v: v > x


def under(x):
    return lambda v: v < x


def fn_limits(volume, difficulty, bugs, mi, mi_vs, exits, args):
    return (
        ("halstead", "volume", "volume", over(volume)),
        ("halstead", "difficulty", "difficulty", over(difficulty)),
        ("halstead", "bugs", "bugs", over(bugs)),
        ("mi", "mi_original", "MI", under(mi)),
        ("mi", "mi_visual_studio", "MI (VS)", under(mi_vs)),
        ("nexits", "sum", "exits", over(exits)),
        ("nargs", "total_functions", "parameters", over(args)),
    )


def file_limits(volume, bugs):
    return (
        ("halstead", "volume", "volume", over(volume)),
        ("halstead", "bugs", "bugs", over(bugs)),
    )


FN_LIMITS = fn_limits(1000, 30, 0.5, 65, 20, 4, 7)
FILE_LIMITS = file_limits(8000, 2)
# --profile: "sdk" (the limits above) for src/, the examples' C and
# scripts/; a ratchet at the maximum measured when the gate was added
# (2026-10-17) for the moqt_chat frontend and e2e scripts, which predate
# it -- they may not get worse.
PROFILES = {
    "sdk": (FN_LIMITS, FILE_LIMITS),
    "frontend": (
        fn_limits(30767, 89.5, 5.11, -17.9, -10.5, 6, 20),
        file_limits(96857, 14),
    ),
    "e2e": (fn_limits(5627, 37.5, 1.18, 41.8, 24.4, 4, 8), file_limits(21638, 4.42)),
}
# Generated data, not code: its volume counts the table's literals.
EXEMPT = ("src/crypto/asymmetric/ecc/p256fixed/p256fixed_table.c",)


def cell(v, width, prec):
    """v right-aligned in width with prec decimals; '-' for null."""
    return "-".rjust(width) if v is None else "%*.*f" % (width, prec, v)


def row(m, where):
    h, mi = m["halstead"], m["mi"]
    cells = (
        (h["volume"], 8, 0),
        (h["difficulty"], 6, 1),
        (h["effort"], 10, 0),
        (h["bugs"], 6, 2),
        (mi["mi_original"], 8, 1),
        (mi["mi_sei"], 7, 1),
        (mi["mi_visual_studio"], 6, 1),
        (m["nexits"]["sum"], 5, 0),
        (m["nargs"]["total_functions"], 4, 0),
    )
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
    return ["%s %.2f" % (lim[2], m[lim[0]][lim[1]]) for lim in limits if broken(m, lim)]


def load(root):
    units = []
    for d, _, names in os.walk(root):
        for n in names:
            with open(os.path.join(d, n)) as f:
                units.append(json.load(f))
    return sorted(units, key=lambda u: u["name"])


def fn_warnings(u, limits):
    return [
        "%s:%d: warning: %s has %s" % (u["name"], s["start_line"], s["name"], b)
        for s in functions(u)
        for b in breaks(s["metrics"], limits)
    ]


def file_warnings(u, limits):
    return [
        "%s:1: warning: file has %s" % (u["name"], b)
        for b in breaks(u["metrics"], limits)
    ]


def checked(units):
    return [u for u in units if u["name"] not in EXEMPT]


def emit(lines):
    sys.stdout.writelines(line + "\n" for line in lines)


def check(units, profile="sdk"):
    """Print every limit of profile broken (compiler warning format);
    their count. An unknown profile raises KeyError."""
    fn, fl = PROFILES[profile]
    lines = [
        w for u in checked(units) for w in fn_warnings(u, fn) + file_warnings(u, fl)
    ]
    emit(lines)
    return len(lines)


def fn_rows(units):
    return [
        row(s["metrics"], "%s@%d@%s" % (s["name"], s["start_line"], u["name"]))
        for u in units
        for s in functions(u)
    ]


def report(units):
    print("per function\n" + COLS)
    print("\n".join(fn_rows(units)))
    print("\nper file\n" + COLS)
    print("\n".join(row(u["metrics"], u["name"]) for u in units))


def profile_of(args):
    """args after --check: [--profile NAME] DIR."""
    return args[1] if args[0] == "--profile" else "sdk"


def main(args):
    if args[0] != "--check":
        report(load(args[0]))
        return 0
    return 1 if check(load(args[-1]), profile_of(args[1:])) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
