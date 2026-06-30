---
description: Every function must have CCN <= 3; count branches before writing, push compound conditions into predicate helpers and branch-clusters into table+function-pointer dispatch.
appliesTo: when writing or editing any function in src/, before running the CCN gate
alwaysApply: true
---

# CCN ≤ 3 for every function

`lizard src --CCN 3 -w` must exit 0. Initial drafts landed at CCN 4–6 almost
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

Do NOT run the whole `just ccn` / `lizard src` while other coders have half-
written files in `src/` — lizard walks all of `src/` and another coder's
in-progress file (CCN 6) fails your green diff (#5). Measure just yours:

```sh
lizard src/<dir>/<file>.c --CCN 3 -w
```

Run the full-tree `lizard src --CCN 3 -w` (part of the commit gate in
build-and-verify.md) only after all coders report done.
