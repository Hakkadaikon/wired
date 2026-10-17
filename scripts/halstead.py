#!/usr/bin/env python3
"""Tabulate rust-code-analysis JSON (one file per source, under argv[1]):
Halstead volume/difficulty/effort/bugs and the maintainability index (MI)
per function, then per file. MI is printed in its three forms: original
(171-based), SEI (with comment weight) and Visual Studio (0..100)."""
import json
import os
import sys

COLS = "  volume   diff     effort   bugs  mi_orig  mi_sei  mi_vs  location"


def row(m, where):
    h, mi = m["halstead"], m["mi"]
    return "%8.0f %6.1f %10.0f %6.2f %8.1f %7.1f %6.1f  %s" % (
        h["volume"], h["difficulty"], h["effort"], h["bugs"],
        mi["mi_original"], mi["mi_sei"], mi["mi_visual_studio"], where)


def functions(space, path):
    for s in space["spaces"]:
        if s["kind"] == "function":
            yield row(s["metrics"], "%s@%d@%s" % (s["name"], s["start_line"], path))
        yield from functions(s, path)


def main(root):
    units = []
    for d, _, names in os.walk(root):
        for n in sorted(names):
            with open(os.path.join(d, n)) as f:
                units.append(json.load(f))
    units.sort(key=lambda u: u["name"])
    print("per function\n" + COLS)
    for u in units:
        for line in functions(u, u["name"]):
            print(line)
    print("\nper file\n" + COLS)
    for u in units:
        print(row(u["metrics"], u["name"]))


main(sys.argv[1])
