---
description: Never commit unless the three-point gate (test + freestanding build + CCN) all pass AND object count equals source count.
appliesTo: before every commit, after editing any C source under src/, before reporting a domain "done"
alwaysApply: true
---

# Build & verification gate

This repo has been corrupted by partial green judgements: a passing `just test`
that was stale, a `| tail` that swallowed a CCN failure, a `just check` that
omitted the freestanding build. Every shortcut below is a real failure that
shipped to `main`. Do not repeat them.

## The three-point gate (all must pass, every commit)

A commit is allowed only when ALL THREE are green in the SAME working tree:

1. `just test` — hosted unity build, all tests pass (assertions on).
2. `just build` — every `src/**/*.c` compiles `-ffreestanding -nostdlib -Werror`.
3. `lizard src --CCN 3 -w` — exits 0 (every function CCN ≤ 3).

Plus the count check (see below). Run them as a single guarded command so a
red result physically cannot reach `git commit`:

```sh
if just test 2>&1 | grep -q "all tests passed" \
   && just build >/dev/null 2>&1 \
   && lizard src --CCN 3 -w; then
    git commit -m "..."
fi
```

## Why each rung exists (each is a logged failure)

- **`just test` alone is not enough** (#7b/#12): hosted test build and the
  freestanding build enable different warnings. `!peer_spin & 1` passed the
  test build but `just build` rejected it under `-Wlogical-not-parentheses`.
  A freestanding-only error reached `main` because the gate lacked `just build`.
- **`lizard` on a subset lies** (#12/#16): gating with `lizard src/<file>.c`
  (MYFILES-only) marks code "green" that the unity build never even compiled.
  Always run `lizard src` over the whole tree.
- **Stale `just test`** (#12): when wiring silently fails, `just test` keeps
  reporting the OLD green. 138 tests / 48 sources were committed un-built.

## Never do this

- `just check 2>&1 | tail && git commit` — the pipe's exit is `tail`'s, so a
  CCN-red `just check` still commits (#7, recurred 3×). NEVER pipe a gate into
  `tail`/`head`/`grep` and then `&&` a commit on the pipe's exit. Use `grep -q`
  for the truthy text AND the tool's own exit, as shown above.
- Chaining gate and commit with `;` (`just check; git commit`) — `;` ignores
  the failure of the gate (#7). Use `&&` / `if`, never `;`.
- Running the whole `just ccn` while parallel coders have half-written files in
  `src/` — lizard walks all of `src/` and a coder's in-progress `retry.c` (CCN 6)
  fails YOUR green diff (#5). During parallel work, measure only your own file
  with `lizard src/<dir>/<file>.c --CCN 3 -w`; run the full `lizard src` gate
  only after all coders report done.

## Count check: objects must equal sources

After any wiring change, verify nothing was dropped from the build:

```sh
[ "$(find src -name '*.c' | wc -l)" = "$(find build -name '*.o' | wc -l)" ]
```

- These counts MUST be equal (#12/#15). A mismatch means a source is not being
  compiled — wiring is broken.
- The count is only trustworthy because `build` emits `build/<full/path>.o`
  preserving directory structure. Do NOT change the build recipe to drop bare
  `<basename>.o` into one dir: `control.c`/`frame.c`/`grease.c`/`vneg.c` share
  basenames and would overwrite each other, silently breaking the count and
  hiding wiring gaps (#15). If you make a count a gate, first guarantee the
  counting method cannot collapse on collisions.

## libc independence is proven by the freestanding build

`just build` compiling every `.c` under `-ffreestanding -nostdlib` IS the proof
that `src/` depends on no libc. Do not add standard headers to make a file
compile; fix the code. See naming-and-unity-build.md for what `src/` may use.

## freestanding runtime gotchas (examples/, self-`_start`)

When code provides its own `_start` (no crt):

- Add `__attribute__((force_align_arg_pointer))` to the entry. `_start` is
  entered with RSP%16==0 but the C ABI assumes %8 after a `call`; SSE
  instructions (e.g. in x25519) segfault on the misalignment (#24a).
- A buffer passed to a view-based (non-copying) API — e.g. a cert DER handed to
  `sdrv_init` which holds it as a view — must outlive the call. Define it in the
  CALLER's scope, not a helper's local, or it dangles the moment the helper
  returns (#24b).
