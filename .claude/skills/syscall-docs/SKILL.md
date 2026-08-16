---
name: syscall-docs
description: >
  Keep docs/syscalls.md in sync with the shared syscall surface
  (src/common/platform/sys/syscall.h facade + the SYS_* numbers in
  src/common/arch/x8664/x8664.h) and any locally-#define'd SYS_* numbers. Use whenever a syscall is added,
  removed, or its call site/purpose changes in this repo — e.g. after adding
  a new `#define SYS_*`, after adding/removing a `syscall1/3/4/6(...)` call
  site, or when asked to "update the syscall docs" / "syscallの説明を更新".
---

# syscall-docs

`wired` is libc-free: every kernel interaction goes through a typed
`wired_arch_<name>` wrapper (`src/common/arch/sysops.h`); the SYS_* numbers,
raw `syscallN` macros, and instruction sequence live in
`src/common/arch/x8664/x8664.h` and are called only inside
`src/common/arch/`. `docs/syscalls.md` is the single table of every syscall this SDK
issues — number, description, and why `wired` calls it. It goes stale the
moment a syscall is added/removed without updating that table, so treat this
skill as a required step alongside any change to syscall usage, not an
afterthought.

## When to run this

- A new `#define SYS_<name> <number>` plus its `wired_arch_<name>` wrapper
  was added to the arch adapter (`common/arch/x8664/x8664.h` + `sysops.h`).
- A `wired_arch_<name>(...)` call site was added, removed, or its purpose
  changed (e.g. new flags, new caller, new subsystem using an existing
  syscall).
- The user asks to update/regenerate/audit the syscall documentation.

## Procedure

1. **Enumerate every syscall definition** (all numbers live in the arch
   adapter; a `#define SYS_` anywhere else is itself a finding):
   ```sh
   grep -n '^#define SYS_' src/common/arch/x8664/x8664.h
   grep -rn '#define SYS_' --include=*.c src/   # must be empty
   ```
2. **Enumerate every call site** and confirm each wrapper is actually used
   (and vice versa — every call site maps to a wrapper in sysops.h):
   ```sh
   grep -rn 'wired_arch_[a-z0-9_]*(' --include=*.c src/ \
       | grep -v 'src/common/arch/'
   ```
3. **For each syscall, read its call site(s)** to confirm (don't guess):
   - which function(s)/file(s):line(s) call it
   - what arguments it's called with and why (flags, socket options, buffer
     sizes/caps — e.g. `WIRED_UDP_SEGMENT`, `WIRED_RECVMMSG_MAX`)
   - which subsystem/feature it serves (client loop, server loop, file I/O,
     RNG, signal handling, etc.)
4. **Diff against `docs/syscalls.md`'s table**: add a row for a new syscall,
   update the "Why wired calls it" cell if the call site's purpose changed,
   remove the row if a syscall was deleted. Keep one row per syscall name,
   not per call site — list multiple call sites in the same cell.
5. **Keep the table's columns**: Syscall | Number | Defined | Description |
   Why `wired` calls it. "Defined" says `syscall.h` (the shared facade +
   arch adapter surface) for every syscall — local defines no longer exist.
6. If the change affects *how* I/O multiplexing works (e.g. moving off a
   single-fd `poll` model), also revisit the "Why `poll`, not `epoll`"
   section — it documents a design decision (single fd per wire loop), not
   just a syscall list entry, and it goes stale independently of the table.
7. Verify the doc still matches reality: re-run the two `grep` commands from
   steps 1-2 and confirm every syscall name appears exactly once in the table
   and every table row has a syscall that still exists in the source.

## Non-goals

- This skill does not add new syscalls or change how they're called — it
  only keeps the documentation truthful after such a change happens
  elsewhere. If asked to add a syscall, do that first (following
  `.claude/rules/naming-and-unity-build.md` and the three-point gate in
  `.claude/rules/build-and-verify.md`), then run this skill.
- Don't speculate about why a syscall is used — always read the actual call
  site. This doc has already had one entry corrected after Reading the code
  disagreed with a first guess.
