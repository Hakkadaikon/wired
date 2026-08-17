---
description: Every symbol is globally unique because the whole repo links as one unity TU; application-facing API gets the wired_ prefix, internal API its module token, and every new name is grep-checked before use.
appliesTo: when naming any function/static/typedef/macro in src/, when adding a new src/<domain>/, when wiring a new file into tests/run.c
alwaysApply: true
---

# Naming & the unity build

`tests/run.c` is a SINGLE translation unit: it `#include`s every production
`.c` once and every `*_test.c` once. So EVERY symbol — public function, `static`
helper, `typedef`, macro, constant — shares one global namespace. Collisions do
not surface until link/wiring time, never in a coder's isolated `$TMPDIR` build.

## Rules that prevent collisions

- **The prefix encodes the audience.** Application-facing API (anything the
  examples call, or that `docs/api-stability.md`'s Stable table lists) is
  `wired_<rest>` / `WIRED_<rest>`. Internal non-`static` API carries its
  module token as the prefix (`sdrv_*`, `moqctl_*`, `bn_*`, macro
  `LEVEL_*`) — no protocol-wide prefix. `docs/api-stability.md` is the
  authority on which side a name falls.
- **The module token must still be distinct.** MECE splits responsibility,
  not namespace — both halves still link into one binary (#17). Historically
  `quic_sent_init` collided across `sentpkt` and `recovery`, and
  `quic_h3_control_open` across `h3run` and `h3`; the fix was
  per-module tokens (`sentpkt_*`, `h3run_*`), which is now the rule itself.
- **Before adding any non-`static` name, grep:**
  ```sh
  grep -rn '<module>_<name>' src/
  ```
  Collisions are invisible until wiring (#3/#16/#17). Catch them at naming time.
- **`static` helpers, `typedef`s, and macros collide too.** The unity TU
  re-defined `static put_bytes`/`take_bytes` (ncid vs connctl), `tag_diff` (gcm
  vs aead), `u64_max` (rtt vs cc), `put_be32` (ipv4 vs sha256), plus duplicate
  SHA-512 constants/macros and `test_path` (#3/#12). The moment you write the
  same small helper a second time, STOP and hoist it to `util/*.h` as `inline`.

## "Missing behavior" is usually an unwired part — grep before you build

In this MECE codebase, "the processing doesn't exist" is frequently "the right
part exists but nothing calls it" (a decoder never reached, an ACK generator
never invoked — successes #15). Before implementing anything, `grep -rn` for
the concept in `src/`; if the part exists, close the gap with one wire, not a
reimplementation.

## Use util/ inline helpers — do not re-roll

`src/util/` already provides the shared primitives. Use them; never write a new
`static` for these (#3):

- `util/bytes.h` — byte copy / put / take
- `util/be.h` — big-endian store/load (`put_be32`, etc.)
- `util/ct.h` — constant-time compare (`tag_diff` and friends)
- `util/num.h` — numeric helpers (`u64_max`, etc.)

If you need a new shared primitive, add it here as `inline`, do not duplicate a
`static` across two domains. `src/` may include ONLY `sys/syscall.h` types and
`util/*` — no standard library headers (this is what `just build` enforces).

## Inline assembly, CPU builtins, and raw syscalls live in common/arch/ ONLY

Every ISA-specific construct — inline asm, naked trampolines, SIMD
instruction wrappers, x86 builtins like `__builtin_ia32_pause` — lives under
`src/common/arch/` (`arch.h` facade, `x8664/` implementation) behind a
`wired_arch_*` / `WIRED_ARCH_*` name. The same goes for the raw syscall
layer: domain files call the typed `wired_arch_<name>()` wrappers
(`common/arch/sysops.h`), never `syscallN(...)` or a `SYS_*` constant, and
a new syscall means adding its number to `x8664/x8664.h` plus a wrapper to
`sysops.h` (see docs/syscalls.md). Do NOT write `__asm__`, an ISA builtin,
or a raw syscall in a domain file. Both greps must stay empty:

```sh
grep -rn '__asm__\|__builtin_ia32' src/ | grep -v common/arch/
grep -rn 'syscall[1-6](\|SYS_[a-z]' src/ | grep -v common/arch/
```

## Wiring a new file into the unity build (tests/run.c is MANUAL)

`justfile` auto-discovers `src/**/*.c` via `find`, but `tests/run.c` is hand-
edited. A new domain needs THREE edits in `run.c`, or it is committed but never
built/tested (#12/#16):

1. `#include "<domain>/<file>.c"` — production source, in the production block.
2. `#include "<domain>_test.c"` — its test, in the `*_test.c` block.
3. `test_<domain>();` — the call, inside `main()`.

After editing, confirm it actually landed and the counts line up:

```sh
grep -c 'include' tests/run.c        # includes present?
grep -c 'test_.*();' tests/run.c     # calls present?
# then the object==source count check from build-and-verify.md
```

String-anchor `sed`/`python` edits to `run.c` silently failed for batches 3+ and
piled up 48 un-wired sources (#12). If you use an anchor, `grep` immediately
after to prove the edit took.

## One domain = one src/<dir>/ (MECE)

Keep each domain in its own `src/<dir>/`. Don't scatter a concern across dirs or
merge two concerns into one dir. MECE is the directory discipline; the prefix
rule above is the (separate) namespace discipline — you need both.
