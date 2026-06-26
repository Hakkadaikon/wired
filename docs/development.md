# Development

How to work on `quic_vibe`: the constraints every change must hold, and the
workflow for adding a domain.

## Hard constraints

These are enforced and non-negotiable; a change that breaks any of them is not
done.

- **No libc, no CRT.** Production sources compile under `-ffreestanding
  -nostdlib` (`just build`). Do not include `<stdio.h>`, `<string.h>`, etc. in
  `src/`. The only place a hosted header appears is `tests/test.h`. Write your
  own small byte loops instead of `memcpy`/`memset`.
- **Direct syscalls only**, through `src/sys/syscall.h`. No libc wrappers. The
  end-to-end data path must not call any network syscall — see "Kernel-free"
  below.
- **x86_64-linux only.** No portability layer, no `#ifdef` for other arches.
- **Cyclomatic complexity ≤ 3 for every function**, enforced by `just ccn`
  (lizard). This shapes the whole codebase: lots of small functions, early
  returns, and table/loop-driven logic instead of nested branches. `lizard`
  counts `&&`, `||`, and `?:` as branches, so factor compound conditions into
  named helper predicates.

## Workflow

1. **Read the RFC first.** Every codec/algorithm is implemented against a
   specific RFC or FIPS section and verified with that document's published
   test vectors. Find the vector before writing code.
2. **Test first.** Add a `tests/<domain>_test.c` with the official vector as a
   golden assertion, plus round-trip and truncated/invalid-input cases. Wire
   it into `tests/run.c` and confirm it fails (Red).
3. **Implement minimally.** Write the smallest code that passes. Reuse existing
   helpers (`util/*.h`, `varint` cursors, the `fsm` engine) before adding new
   ones. The first lazy solution that works and stays CCN ≤ 3 is the right one.
4. **Keep the gate green.** Run `just check` (ccn + test). When a function hits
   CCN 4, split out a helper — usually a boolean predicate for a compound
   condition, or a sub-step that does part of the work.
5. **Micro-commit.** Conventional commits in ~30–50 line logical units:
   `feat(<domain>): ...` for code, a separate `test(<domain>): ...` for its
   tests. Keep `feat` and `test` as distinct commits.

## Adding a domain

A domain is `src/<name>/<name>.h` + `src/<name>/<name>.c`:

- The header holds types, constants, and prototypes; the `.c` holds the
  implementation with `static` helpers.
- Add the `.c` to the `build` recipe in the `justfile` so it is compiled
  freestanding.
- Add `#include "<name>_test.c"` and the `test_<name>()` call to
  `tests/run.c`. Tests include the `.c` directly, so a domain's implementation
  is compiled into the test translation unit; if two domains define a helper
  with the same name, that collision surfaces here — promote the shared helper
  to an inline function in `util/`.

## Kernel-free data path

The end-to-end path uses `net/memlink` (an in-process datagram FIFO) and the
userspace `net/ipv4` + `net/udp4` stack. It must never call `socket`,
`sendto`, `recvfrom`, or `bind`. Verify mechanically:

```sh
grep -rn "SYS_socket\|SYS_sendto\|SYS_recvfrom\|SYS_bind" \
  src/endpoint src/net src/protect src/tls src/frame   # expect no matches
```

Sockets exist only in `io/udp` as an optional real-network path, kept out of
the end-to-end flow.

## Verification beyond tests

For changes involving state machines, concurrency, or critical algorithms, the
design and key properties are checked with model checking (TLA+) and proof
(Lean 4) before/alongside implementation, and the resulting invariants and
proven predicates are turned into the golden tests above. Those artifacts are
kept out of the repository; what lands here is the verified code and the tests
derived from it.
