[Docs](../README.md) › [Features](README.md) › Ledger format

# Requirement ledger format

Every ledger in docs/features/ is an EARS requirement ledger for ONE spec,
mapping each requirement to the existing test that demonstrates it. The
goal: untested requirements must be visible at a glance. This page is for
contributors who add or edit a ledger; `scripts/check_features.py`
(`just features-check`, run in CI) enforces the machine-checkable rules.

## File skeleton (follow exactly)

```markdown
[Docs](../README.md) › [Features](README.md) › RFC 9000

# RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport

EARS requirement ledger extracted from the spec text
(`tasks/specs/rfc9000.txt`, not in git). Each requirement carries the test
that demonstrates it; an unchecked box with no test line is an open gap.
Status as of 2026-07.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: NN/MM tested, KK indirect, LL untested.**

## §16 Variable-Length Integer Encoding

- [x] 9000-001 (§16) The server shall decode the two most significant bits
  of the first byte as the variable-length integer length.
  - test: `tests/transport/varint_test.c` — `test_varint_decode`
- [~] 9000-002 (§16) When encoding a variable-length integer, the server
  shall not use a longer encoding than necessary.
  - evidence: exercised by every frame-codec round-trip test; no dedicated
    minimal-length assertion.
- [ ] 9000-003 (§16) If a varint exceeds 2^62-1, then the server shall
  reject the encoding.

## Out of scope

Client-only or operator-level requirements this server SDK does not
implement, excluded from the coverage denominator:

- (§6.2) Client-initiated version negotiation response handling — client
  behavior.
```

## Rules

1. **IDs**: `<stem>-NNN`, three digits. A new ledger numbers its items in
   spec order. After that an ID is permanent, because other pages (e.g.
   known-limitations.md, GitHub issues) cite it: a deleted item leaves a gap,
   a new item takes the next free number even when that puts it out of
   order within its section, and an ID is never reused or renumbered
   (the checker rejects an ID used twice). A suffix letter (`MQ18-118a`)
   marks an item split out of an existing one. The RFC 9000 ledger still
   uses the placeholder `9000-XXX`, which the uniqueness check skips.
   Stems: rfc9000 → `9000`, fips197 → `F197`, fips186-4 → `F186`,
   fips180-4 → `F180`, fips198-1 → `F198`, sp800-38d → `S38D`,
   draft-ietf-webtrans-http3-15 → `WTH3`,
   draft-ietf-moq-transport-19 → `MOQT`.
2. **EARS phrasing** (pick the matching template, English):
   - Ubiquitous: "The server shall X."
   - Event-driven: "When T, the server shall X."
   - State-driven: "While S, the server shall X."
   - Unwanted behavior: "If C, then the server shall X."
   - Optional feature: "Where F, the server shall X."
   The system name is "the server" (wired is a server SDK); for pure
   library primitives (crypto, codecs) use "the implementation".
3. **Extraction scope**: every normative MUST / MUST NOT / SHALL / SHOULD /
   SHOULD NOT / REQUIRED statement relevant to a server-side implementation,
   plus the spec's central algorithms even when phrased descriptively (e.g.
   a KDF's derivation steps, a state machine's transitions).
   Over-extraction is safe; omission is dangerous — when in doubt, include.
   Group items under `##` headings mirroring the spec's own section
   structure, in spec order.
4. **Out-of-scope items** go in the final `## Out of scope` section as plain
   bullets (no checkbox, no ID), each with a one-phrase reason. Client-only
   behavior, operator guidance, and algorithms the SDK deliberately does not
   ship belong here — never silently dropped, never counted in the summary.
5. **Test references** — the checker enforces this format EXACTLY:
   ``- test: `tests/<dir>/<file>` — `<function>` ``
   - The file path must exist in the repo; the function name must appear in
     that file. NEVER cite a test you have not grep-verified. If you cannot
     find a real test, the item is `[~]` (with an evidence line) or `[ ]` —
     an honest gap beats an invented reference.
   - The cited test must be reachable from `tests/run.c` `main()` AND drive
     code that a production path (`examples/` -> srvrun/srvloop/sdrv/
     moqtrun) calls. A test of a helper with no production caller is at
     most `[~]` evidence. This holds for library and codec items phrased
     "the implementation shall" too: a primitive that only a test, a fuzz
     harness or an unshipped client calls is `[~]` (or `[ ]` when no
     production path exercises it at all), with an evidence or gap line
     saying so.
   - SHOULD / RECOMMENDED rules are phrased "should", MUST rules "shall".
   - Multiple tests: repeat the `- test:` line.
   - Golden-vector headers (`tests/*_golden.h`) and fuzz harnesses
     (`fuzz/fuzz_*.c`) may also be cited on `- test:` lines.
   - `[~]` items use `- evidence:` (free text) instead of `- test:`.
   - An interop-only demonstration is `[~]` with an evidence line naming the
     testcase, e.g. `- evidence: interop testcase `keyupdate` (see
     [Interop](../interop.md)); no dedicated unit test.`
6. **Where to look for tests**: `tests/{transport,crypto,tls,app,common}/
   <domain>_test.c`, functions `static void test_*`. Hint maps:
   `docs/test-coverage.md` (vector locations). Verify with grep; the hint
   map is NOT evidence.
7. **Summary line**: `**Coverage: NN/MM tested, KK indirect, LL untested.**`
   where MM = total checkboxed items, NN = `[x]`, KK = `[~]`, LL = `[ ]`.
   Boxes under a `## Not implemented`, `## Out of scope`,
   `## Experimental ...` or `## Informational ...` heading are not counted.
   Counts must match the actual boxes, and the README rows and Total line
   must match the ledgers; `python3 scripts/check_features.py --fix`
   rewrites all three from the boxes.
8. Keep each requirement one sentence. Cite the spec section in parentheses
   after the ID. Do not editorialize; gap notes are allowed as a short
   `- gap:` line when the reason an item is untested is already known.
9. Write the file in English (docs/ convention). Wrap prose at ~79 columns.
