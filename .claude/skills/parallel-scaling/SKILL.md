---
name: parallel-scaling
description: >
  Use when deciding how many subagents to run in parallel, when asked to
  "increase parallelism" / "use more agents" / "並列数を上げて", or before
  launching a batch of background agents. Measures CPU/memory/load of the real
  machine and classifies the work as parallelizable vs serial vs indivisible to
  pick a safe maximum, instead of guessing. Trigger on "how many agents",
  "spin up more workers", "parallelize this", "max out the cores", or when a
  parallel batch is about to start saturating the box.
---

# parallel-scaling

Pick the subagent count from the real machine and the real work, not from a
hunch. Too many agents saturate CPU/memory and run *slower*; too few waste the
box. Equally important: some work must not be parallelized at all.

## 1. Measure the environment first

Run these before choosing a number. They are cheap and decide everything.

```sh
nproc                                                          # CPU cores
awk '/MemTotal|MemAvailable/ {print $1, int($2/1024) "MB"}' /proc/meminfo   # total + free RAM
cut -d' ' -f1-3 /proc/loadavg                                  # load avg 1/5/15 min
```

Read them as:
- `nproc` → hard ceiling on useful CPU-bound concurrency.
- `MemAvailable` → how many agents fit before swapping.
- `loadavg` over `nproc` → already saturated; do **not** add more.

## 2. The parallelism formula

For **CPU-bound** agents (e.g. a coder that runs a clang build each iteration):

```
safe_parallel = min( nproc - 1,
                     floor(available_mem_MB / 700),
                     N_independent,
                     8 )
```

- `nproc - 1`: leave one core for the orchestrator and the OS.
- `700 MB/agent`: measured rule of thumb for a clang freestanding build. Tune
  per repo — a heavier build wants a bigger divisor, a light one smaller.
- `N_independent`: you cannot run more agents than you have independent units
  of work (see §3).
- `8`: a soft cap; coordination overhead grows past this even on big boxes.

Empirical anchor (so the numbers aren't abstract): on **4 cores, ~2.4 GB free**,
the practical ceiling was about **6 concurrent coder agents**. Beyond that,
context-switching plus memory pressure made the whole batch slower.

These constants are environment-dependent. **Measure (§1), then plug in.** If
`loadavg` climbs past `nproc` mid-batch, drop the count on the next wave.

I/O-bound agents (fetch, search, read-only exploration) use little CPU/RAM and
can go wider — but they are rarely the bottleneck, so still start from the
formula and only widen if load stays low.

## 3. Parallelizable vs serial vs indivisible

Before raising the count, decide whether the work *may* be parallelized at all.

**Independent — safe to run at max parallel.**
Implementation tasks that each create *separate new files* and never touch each
other's files or outputs. This is where parallelism pays off.

**Serial — must run one at a time, regardless of core count:**
- Edits to a **shared file** (in this repo: `tests/run.c`, the `justfile`; in
  general any shared config/registry/manifest). Two agents editing the same
  file collide or clobber.
- `git add` / `git commit`. The git index is repo-global state — parallel
  commits cross-contaminate even when the file sets are disjoint.
- **Dependent** stages: if B consumes A's output, B cannot start until A is done.

**Indivisible — do not split at all:**
A single state machine, a single integration layer, a single set of mutually
entangled invariants. Splitting it across two agents just builds the same thing
twice. Examples: one steady-loop body; one TLA+ spec (TLC explores a single
spec exhaustively — it does not divide).

If someone says "use more agents" but the independent work is exhausted, the
honest answer is: **more parallelism here is useless** — say so instead of
spawning agents that fight over shared files or duplicate indivisible work.

## 4. The pipeline pattern (what works)

Fastest reliable shape:

```
implement (independent, max parallel)  →  wire (serial, ONE agent)  →  ledger / verify (ONE agent)
```

Fan out the independent implementation at the count from §2. Funnel everything
that touches shared files (the wiring: `run.c`, `justfile`) through a **single**
agent. Then update the ledger / run verification once, serially. Never let the
wiring step run parallel.

## 5. Decision checklist

1. Measure: `nproc`, `MemAvailable`, `loadavg` (§1).
2. Classify the pending work: independent / serial / indivisible (§3).
3. Count `N_independent`.
4. `safe_parallel = min(nproc-1, floor(mem_MB/700), N_independent, 8)`.
5. Run serial stages (wiring, commit) with exactly **one** agent.
6. If the work is indivisible, do **not** split — state that plainly.
7. Watch `loadavg`; if it passes `nproc`, reduce the count on the next wave.
