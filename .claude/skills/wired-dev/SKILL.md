---
name: wired-dev
description: >
  Use when modifying, adding to, or reviewing code in the wired libc-free
  QUIC SDK in C — covers its libc-free / CCN<=3 / unity-build constraints, the
  three-point verification gate, the unity-build name-collision pitfalls, the
  view-API and freestanding-_start traps, and the parallel-implement /
  serial-wire workflow, plus how to diagnose a slow handshake (profile-first,
  peer qlog, stage timestamps, microbenchmarks) and speed up crypto safely.
  Trigger on any change under src/ or tests/, on "add a domain", "wire a test",
  "why does run.c fail to build", "obj count mismatch", "CCN too high", on
  "handshake is slow" / "appconnect takes seconds" / "why is it slow" / "speed
  up", or before committing C changes in this repo.
---

# wired developer guide

A libc-free QUIC SDK in C. The constraints here are unusual; touching the code
without knowing them fails in ways a normal C project never would. This is the
complete guide to changing this repo safely. Every pitfall below cost a real
debugging session (see `tasks/lessons/`); each one lists why, how to avoid it,
and how to detect it.

Read top to bottom the first time: Architecture -> Add/modify a domain ->
the three-point gate -> pitfalls. After that, the gate and pitfalls are the
parts you reread.

## 1. Architecture and hard constraints

- **libc-free, freestanding, x86_64-linux only.** Built with
  `-ffreestanding -nostdlib -static -fno-builtin`. There is no libc.
- **No standard headers.** Do not `#include <string.h>`, `<stdint.h>`,
  `<stdlib.h>`, etc. The only outside surface is direct syscalls via
  `src/sys/` and the shared inline helpers in `src/util/`.
- **`src/util/` holds the shared primitives.** `util/be.h` (big-endian
  store/load), `util/bytes.h` (byte copy/compare), `util/ct.h` (constant-time
  compare), `util/num.h` (min/max etc). Use these; do not hand-roll your own
  `static put_be32` / `take_bytes` / `u64_max` in a domain file (see pitfall
  #3).
- **CCN <= 3.** `lizard` counts every `&&`, `||`, `?:`, `if`, `for`, `while`
  as one branch. The gate is `lizard src --CCN 3 -w` and it must exit 0. Plan
  the branch count before writing; pull compound conditions into a small
  `static int cond(...) { return a && b; }` predicate, and split three
  consecutive `if (!put(...)) return 0;` lines into head/body helpers.
- **MECE: one domain, one directory.** `src/<domain>/` owns one
  responsibility. Public API is prefixed `quic_<domain>_`.
- **Unity build — the single biggest trap.** `tests/run.c` is one translation
  unit that `#include`s every production `.c` exactly once and every
  `*_test.c`. So *every symbol in the whole codebase shares one global
  namespace*: a `static` helper, a `typedef`, a macro, or a public function
  with the same name in two different files is a redefinition error. Single
  global uniqueness is mandatory. Most pitfalls below are consequences of this.

## 2. How to add or modify a domain

1. **Pick a name and check for collisions first** (pitfall #17 — collisions
   only surface at wire-up, so prevent them at naming time):
   ```sh
   grep -rn 'quic_<domain>_' src/        # public API prefix free?
   grep -rn '<helpername>' src/          # any static helper / macro clash?
   ```
2. **Create `src/<domain>/<domain>.{h,c}`.** Public functions are
   `quic_<domain>_...`. For shared byte/be/constant-time work, include the
   `util/*.h` inline helpers instead of writing your own statics (#3).
3. **Write `tests/<name>_test.c`** with `void test_<name>(void)` using the
   `CHECK(...)` macro from `tests/test.h` (see `tests/path_test.c` for the
   shape). Tests do **not** include production `.c` files — `run.c` does that.
4. **Wire it up — this is the serial step (#2, #18, #21).** Three edits, all
   in shared files, so one person/agent does them in one pass:
   - `tests/run.c`: add `#include "<domain>/<domain>.c"` (production) and
     `#include "tests/<name>_test.c"` if applicable, plus the test include and
     a `test_<name>();` call in `main`.
   - `justfile` needs no edit: `build` auto-discovers `src/**/*.c` via `find`.
5. **Run the three-point gate (section 3) and the count check before
   committing.**

A single-file green ($TMPDIR driver) does **not** prove integrated green
(#16). The truth is the gate after wire-up, not a standalone compile.

## 3. The three-point verification gate (the core of not regressing)

Before any commit, all three must be green, plus the count check. Copy-paste:

```sh
just test    # unity build of all *_test.c -> must print "all tests passed"
just build   # every src/**/*.c compiled -ffreestanding -Werror -> exit 0
lizard src --CCN 3 -w                          # CCN gate -> exit 0
```

Count check — wiring silently fails and you commit code that is never built
or tested (#12, #15). Verify the numbers match:

```sh
[ "$(find build -name '*.o' | wc -l)" = "$(find src -name '*.c' | wc -l)" ] \
  && echo "obj==src OK" || echo "WIRING MISMATCH"
```

Why each leg:
- `just test` alone is not enough: host test build and freestanding build
  enable different warnings. `!peer_spin & 1` passed `just test` but failed
  `just build` under `-Wlogical-not-parentheses` (#7b).
- `just build` proves libc independence for *every* domain.
- `lizard` enforces CCN<=3 across all of `src`.
- The count check catches wire-up that didn't actually land — a partial
  ("MYFILES only") gate reports unbuilt code as green (#12, #16).

`build` writes path-qualified objects `build/<path>.o`, so same-basename files
in different dirs (`control.c`, `frame.c`, ...) don't overwrite each other and
the count stays accurate (#15). For fast inner-loop builds use `just ninja`.
All compiler flags live in the `justfile` — change them there, nowhere else.

**Never pipe the gate into the commit.** `just check 2>&1 | tail && git commit`
makes the pipeline exit 0 (tail succeeds) even when CCN is red, and a red
commit lands (#7, #7b). Gate and commit are separate steps:

```sh
if just test 2>&1 | grep -q "all tests passed" \
   && just build >/dev/null 2>&1 \
   && lizard src --CCN 3 -w; then
  git commit ...        # only here
fi
```

## 4. Common pitfalls (each maps to a real failure)

- **Unity-build name collisions (#3, #15, #17).** Same-named `static` helper,
  function, `typedef`, or macro in two files collide in the one TU — even
  though the files are unrelated. *Avoid:* prefix domain symbols, route shared
  helpers through `util/*.h` inline, give public API a `quic_<domain>_` prefix.
  *Detect:* `grep` before naming (section 2.1); the collision shows up as a
  redefinition error in `just test` / `just build` after wire-up.

- **Single-file green is not integrated green (#16).** A coder reporting "all
  tests passed / CCN<=3" from a $TMPDIR driver can still go red in the unity
  build (static/typedef/macro clash, public-name clash, another file's
  pre-existing CCN>3 exposed by `lizard src`). *Avoid/Detect:* judge only by
  the section-3 gate after wiring, never by a standalone compile.

- **Basename collision breaks the count (#15).** If objects aren't
  path-qualified, two `frame.c` in different dirs produce one `.o` and the
  obj==src count silently passes while a file is missing. The `justfile`
  already emits `build/<path>.o`; keep it that way. *Detect:* the count check
  above.

- **Wiring anchors drift -> unverified commits pile up (#12).** String-anchor
  `sed`/`python` edits to `run.c` can stop matching and silently no-op;
  138 tests / 48 sources once sat committed-but-unbuilt. *Avoid:* edit
  `run.c` by hand or with a verified anchor, then immediately `grep` that the
  include/call actually landed, then run the count check.

- **Parallel commits collide via the shared git index (#21, #2, #18).** The
  index is one repo-wide resource; two agents running `git add`/`git commit`
  in parallel mix each other's diffs in, even on different files. *Avoid:*
  parallelize *editing* only; serialize all `git add`/`commit` into one pass.

- **Freestanding `_start` and view-API traps (#24).** A hand-written `_start`
  enters with RSP%16==0 but the C ABI expects %8 after a call, so SSE
  instructions fault — add `__attribute__((force_align_arg_pointer))` to your
  entry. And view-based APIs (e.g. `sdrv_init` holding `cert_der` without
  copying) keep a pointer, not a copy: the caller must keep that buffer alive
  for the whole hold period. Put such buffers in the caller's scope, not a
  helper's locals.

## 5. Verification layers (what to use where)

Match the tool to the property; do not over-verify (#1, #2 in successes):

- **State machines / concurrency / protocol transitions -> TLA+** (key update,
  path validation, close lifecycle, the connection event loop). Run the
  mutation oracle until survivor=0; bake every forbidden transition it finds
  into a C test as a rejection case.
- **Critical crypto / math properties -> Lean** (AEAD round-trip and tamper
  detection, e.g. the Retry tag). Prove it, then the proved predicate becomes
  the test.
- **Everything else (pure codecs) -> TDD only.** Round-trip + golden vectors.
  TLA+/Lean on a pure codec is over-engineering (YAGNI).

For RFC wire formats, take constants and test vectors from the IETF primary
source plus official vectors, and recompute them yourself — external fetch/
search tools truncated RFC 9001 Appendix A and returned a wrong nonce once
(#6). When a full golden vector isn't obtainable, combine component vectors +
round-trip equality + tamper detection + a hand-computable intermediate value
(successes #7).

- **Speeding up a crypto primitive -> differential test against the slow one.**
  Keep the slow-but-obviously-correct implementation as an oracle and check the
  fast version on random + boundary inputs (e.g. `modulus-1`). Hand-derived
  reductions (Solinas word rearrangement, Montgomery CIOS carries) are easy to
  get subtly wrong; the diff test catches it in one run. If the oracle is
  expensive (the generic Fermat inverse was ~91ms each), spot-check a handful
  rather than the whole batch, or the test itself times out. Recompute any
  baked-in constants in a second tool (Python) and verify the limbs match the
  existing ones before committing them.

## 6. Parallel workflow (fast and collision-free)

- **Implement in parallel, wire in serial.** Independent domains (separate new
  files) go to parallel workers; the worker touches *only its own new files*.
- **One serial pass owns the shared files** — `tests/run.c`, the `justfile`
  edits (none needed normally), and all git commits. This is the only safe
  split because `run.c` and the git index are shared resources (#2, #18, #21).
- After wiring, run the full section-3 gate (all-TU build + all-freestanding
  build + `lizard src` + count check) once, then commit.

## 7. Performance diagnosis (measure before you touch anything)

A "the handshake is slow" report once cost two wasted deploy round-trips: the
4.6s appconnect *looked* like PTO backoff (333ms × exponential ≈ 4.6s), so two
real-but-unrelated bugs (a fixed-PN-0 Finished ACK, a sub-1200 server Initial)
were fixed first. The actual cause was a 885ms P-256 scalar multiply — server
compute, not the network. The fix that mattered was a faster field reducer.
Diagnose in this order; each step turns a guess into a fact:

- **Profile before guessing.** A matching number (4.6s ≈ PTO累積) is circumstantial,
  not a cause: PTO is the *symptom* (curl waited), not the thing that made it
  wait. Every guess-fix burns a rebuild+redeploy+remeasure round-trip whether it
  hits or misses. Take the measurement first.
- **The peer's qlog is the fastest oracle.** Encrypted wire hides meaning; a
  capture shows reachability only. Pass `QLOGDIR` to the client (curl/quiche
  emit JSON-SEQ) and read it: it showed curl sent its ClientHello at t=0.25ms,
  got the first server packet at t=4839ms, and never retransmitted — proving the
  stall was server-side compute, not loss or the network. (`SSLKEYLOGFILE` for
  keys.)
- **Stage timestamps pinpoint the gap.** Once it's "inside the server", build
  with `-DQUIC_DEBUG` (each log line carries a CLOCK_REALTIME stamp) and read the
  *deltas* between pipeline boundaries (`Initial received` → `ClientHello
  received` → `flight built`). One run shows which two lines the time vanishes
  between — faster than suspecting one function at a time.
- **In-process microbenchmarks confirm the culprit.** Write a tiny
  `clock_gettime` loop in `$TMPDIR` over each primitive (x25519 / sha256 /
  fp_mul / fp_inv / ec_mul / sign) and read the ms. This is first-choice over a
  profiler: faster to write, and the libc-free core compiles fine under host
  clang for measurement. It put 98% of signing on `fp_inv mod n` immediately,
  with no remote access.
- **Stop at the dominant term.** After killing the big one, measure whether the
  next term shows up in the SLA before touching it. Here the field reducer took
  the scalar mul 885ms→1ms (Solinas mod p) and the order inverse 91ms→0.02ms
  (Montgomery mod n): appconnect 4.6s→17ms (~260×), test suite 3m31s→2s. The
  remaining 17ms is network RTT — the real floor; a comb-table ec_mul (1.5→0.5ms)
  was dropped as YAGNI. See `tasks/lessons/performance.md`.
