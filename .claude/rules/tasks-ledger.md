---
description: How this repo's tasks/ ledgers are kept honest — archive todo.md before repurposing it, record interop PASSes in the matrix format with a log pointer, update ledgers at commit time, and close finished documents.
appliesTo: when updating tasks/todo.md or any tasks/*.md ledger, when recording an interop result, when finishing or abandoning a plan/handoff document
alwaysApply: true
---

# tasks/ ledger discipline

`tasks/` is gitignored, so a ledger overwritten is a ledger LOST — the AF_XDP
epoch's records are gone because `todo.md` was repurposed in place. The generic
principles (one source of truth per ledger, closed markers, evidence pointers)
live in the hymme `ledger-flow` skill; this file is the wired-specific
concretes.

- **Before repurposing `todo.md` for a new epoch, archive it** as
  `todo-<epoch>-done.md` (the way `todo-http3-done.md` was). Never overwrite in
  place.
- **Interop PASS entries follow the quic-interop-matrix.md format**: root
  cause + fixing commit + regression check + the `logs_*/` path of the run
  that proves it. A PASS without a log pointer is how the ecn misrecording
  happened (see rfc-and-verification-layers.md on reading the runner's
  verdict).
- **Update the ledger in the same breath as the commit.** R-17..R-20 sat
  unchecked after their commits landed; a ledger that lags the history is
  worse than none, because it reports done work as open.
- **Close finished documents**: when a plan/handoff/snapshot document is done
  or superseded, add one line at the top — `closed (YYYY-MM-DD), successor: X`.
  A resume document points at ONE current entry point, never a chain of
  redirects.
