---
description: Every function must have CCN <= 3; count branches before writing, push compound conditions into predicate helpers and branch-clusters into table+function-pointer dispatch.
appliesTo: when writing or editing any function in src/, examples/*/*.c or scripts/, before running the CCN gate
alwaysApply: true
---

# CCN ≤ 3 for every function

Scope: src/ and the examples' C (`just ccn`, `just lint`, `just
halstead-check`), scripts/ Python (CCN <= 3 in `just py-check`, Halstead
in `just halstead-check`). The moqt_chat frontend (CCN <= 10) and e2e
scripts are capped separately in `just js-check`.

Two more per-function limits ride the same gates: nesting depth ≤ 2
(`just ccn`, lizard ND) and cognitive complexity ≤ 4 (`just lint`,
clang-tidy). `just metrics` / `just cognitive` print the current values.
`just halstead-check` adds Halstead volume/difficulty/bugs, MI, exits (<= 4)
and parameters (<= 7) per function, and volume <= 8000 / bugs <= 2 per
.c/.h file (limits in scripts/halstead.py). A function over volume ~1000 is
too long: extract steps before it lands. A file nearing the limit gets a
new sibling `<stem>_<topic>.c`; cross-piece helpers go in `<stem>_impl.h`
with the module prefix (hot crypto helpers as `static inline` there, or the
per-object build stops inlining them: P-256/AES-GCM lost 40-65%), and the
new file is wired into tests/run.c (and any fuzz harness that includes the
base .c).

`just ccn` must exit 0. Initial drafts landed at CCN 4–6 almost
every time and had to be re-split (#4). Count branches BEFORE writing — removing
them afterward is expensive.

## How lizard counts (each adds +1)

`&&`, `||`, `?:`, `if`, `for`, `while` — EACH is one branch. The misses that
caused repeated CCN 4 (#4):

- `if (!take(...) || cond) return 0;` — the `||` is +1 on top of the `if`.
- Three back-to-back `if (!put(...)) return 0;` — +1 each.
- A `?:` buried in an expression — +1, easy to overlook.

## Patterns that keep CCN ≤ 3

- **Compound condition → predicate helper.** Don't inline `a && b`:
  ```c
  static int cond(...) { return a && b; }   /* the && lives here, not the caller */
  ```
- **3+ sequential `if (!put) return` → split into 2 helpers** (head/body), so
  no single function carries all the guards (#4).
- **A cluster of branches → table-driven dispatch + function pointers.** Replace
  a long `if/else` or `switch` chain with a lookup table mapping case →
  handler function pointer; the dispatch itself stays O(1) and low-CCN.

## During parallel work, measure your file only

Do NOT run the whole-tree `just ccn` while other coders have half-
written files in `src/` — lizard walks all of `src/` and another coder's
in-progress file (CCN 6) fails your green diff (#5). Measure just yours:

```sh
just ccn src/<dir>/<file>.c
```

Run the full-tree `just ccn` (part of the commit gate in
build-and-verify.md) only after all coders report done.
