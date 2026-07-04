---
description: Never commit unless the three-point gate (test + freestanding build + CCN) all pass AND object count equals source count. Before pushing, also check every job in .github/workflows/ that your diff's file types can affect.
appliesTo: before every commit, after editing any C source under src/, before reporting a domain "done", before every push to main
alwaysApply: true
---

# Build & verification gate

This repo has been corrupted by partial green judgements: a passing `just test`
that was stale, a `| tail` that swallowed a CCN failure, a `just check` that
omitted the freestanding build. Every shortcut below is a real failure that
shipped to `main`. Do not repeat them.

## The three-point gate is NOT the whole CI — check the workflow list too

The three-point gate below catches most logic/build regressions, but it is a
LOCAL SUBSET of `.github/workflows/`. A fully green three-point gate has still
shipped a red CI run to `main` (2026-07-05): `ci.yml` also runs `fmt-check`
(`clang-format --dry-run --Werror`) and `lint` (clang-tidy), neither of which
`just test`/`just ninja`/`lizard` exercises; `docs.yml` runs `just docs`
(doxygen, `WARN_AS_ERROR`) on every push to `main` and is a SEPARATE workflow
the three-point gate never touches at all.

Before pushing (not just before committing), run this once per session (or
whenever `.github/workflows/*.yml` might have changed) and match your diff's
file types against it:

```sh
find .github/workflows -type f
```

As of writing, the jobs are:

| Workflow  | Job(s)                          | Triggers on                       | Local equivalent |
|-----------|----------------------------------|------------------------------------|-------------------|
| `ci.yml`  | `fmt-check`                      | any `.c`/`.h` touched              | `just fmt-check` (needs the pinned clang-format — see caveat below) |
| `ci.yml`  | compile (`just ninja`)           | any `src/**/*.c`                   | part of the three-point gate |
| `ci.yml`  | test (`just test`)               | any `src/**/*.c`, `tests/**/*.c`   | part of the three-point gate |
| `ci.yml`  | ccn (`just ccn`)                 | any `src/**/*.c`                   | part of the three-point gate |
| `ci.yml`  | lint (`just lint`, clang-tidy)   | any `src/**/*.c`                   | `just lint` (needs the pinned clang-tidy — same caveat) |
| `docs.yml`| build+deploy (`just docs`)       | any push to `main` (struct/enum/fn doc comments in `src/**/*.h`) | `just docs` (doxygen; pure-hosted, usually runnable without nix — see below) |

If your diff touches `src/**/*.h` (adding/renaming a struct or union member,
a public function, an enum) or any `.c`/`.h` formatting, do not stop at the
three-point gate — also run `just docs` locally (doxygen has no libc-free
constraint and commonly runs outside `nix develop`) and, when possible,
`just fmt-check`/`just lint` through the pinned toolchain before pushing.

### When the sandbox blocks `nix develop`

`nix develop` needs to write `~/.cache/nix/fetcher-locks/*.lock`; some sandboxed
execution environments deny that write even though the file itself is
writable, so `nix develop -c <recipe>` fails with a "Read-only file system"
error that has nothing to do with the repo. When this happens:

- Do NOT trust a host-installed `clang-format`/`clang-tidy` to match the pinned
  version in `flake.lock` — a version skew silently reformats or reflows
  differently (2026-07-05: local 18.1.3 vs. CI's newer pin disagreed on a
  doc-comment's line-wrap). If you must format by hand, copy the EXACT
  layout (spacing, wrap column, line breaks) of the nearest existing sibling
  declaration instead of composing your own — do not trust your own comment
  formatting to survive `fmt-check` unverified.
  - Concretely: prefer a plain preceding `/** ... */` block over `/**< ... */`
    inline trailing form when adding one new struct member near existing
    ones — the trailing form's column alignment is what disagreed across
    clang-format versions last time.
- `just docs` (doxygen) has no `-ffreestanding`/libc constraint, so it is far
  more likely to run with a bare host `doxygen` than the clang-format/clang-tidy
  jobs are. Try it directly before assuming it needs `nix develop`.
- If neither can be verified locally, say so explicitly, push, and watch the
  actual workflow run (`gh run list` / `gh run view --log-failed`) rather than
  declaring the change done on the three-point gate alone.

## The three-point gate (all must pass, every commit)

A commit is allowed only when ALL THREE are green in the SAME working tree:

1. `just test` — hosted unity build, all tests pass (assertions on).
2. `just ninja` — every `src/**/*.c` compiles `-ffreestanding -nostdlib
   -Werror` to a path-qualified `build/<path>.o`. (This is the raw compile
   step. `just build` = `fmt` + `ninja` + `lint`; the gate uses `ninja`
   directly so formatting/lint side effects and lint's non-fatal findings
   can't corrupt the pass/fail signal.)
3. `lizard src --CCN 3 -w` — exits 0 (every function CCN ≤ 3).

Plus the count check (see below). Run them as a single guarded command so a
red result physically cannot reach `git commit`:

```sh
if just test 2>&1 | grep -q "all tests passed" \
   && just ninja >/dev/null 2>&1 \
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

`just ninja` compiling every `.c` under `-ffreestanding -nostdlib` IS the
proof that `src/` depends on no libc (`just build` runs this plus `fmt` and
`lint`). Do not add standard headers to make a file compile; fix the code. See
naming-and-unity-build.md for what `src/` may use.

## freestanding runtime gotchas (examples/, self-`_start`)

When code provides its own `_start` (no crt):

- Add `__attribute__((force_align_arg_pointer))` to the entry. `_start` is
  entered with RSP%16==0 but the C ABI assumes %8 after a `call`; SSE
  instructions (e.g. in x25519) segfault on the misalignment (#24a).
- A buffer passed to a view-based (non-copying) API — e.g. a cert DER handed to
  `sdrv_init` which holds it as a view — must outlive the call. Define it in the
  CALLER's scope, not a helper's local, or it dangles the moment the helper
  returns (#24b).
