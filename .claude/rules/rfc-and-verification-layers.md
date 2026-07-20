---
description: RFC code follows IETF primary sources with section-number comments and self-recomputed vectors; choose the right verification layer (TLA+ for state, Lean for crypto, TDD for the rest) without mixing or overusing them.
appliesTo: when implementing any RFC behavior, deriving crypto/protocol constants, or deciding how to verify a non-trivial change
alwaysApply: true
---

# RFC compliance & verification layers

## RFC implementation

- Implement strictly against the **IETF primary source** (the RFC text), not a
  blog or a search snippet. Cite the section in a comment (e.g. `RFC 9001 5.8`),
  matching the style of existing commits/code.
- **Re-derive official constants/vectors yourself before baking them into a
  test.** External tools were wrong: WebFetch truncated RFC 9001 Appendix A and
  could not return the full ClientHello; WebSearch returned a nonce as `...255a`
  when the correct byte was `5c ^ 02 = 5e`, and the test failed on the bad value
  (#6). XOR / length / offset are hand-checkable — do the math, don't trust the
  snippet's hex.
- When a full golden vector cannot be retrieved, do NOT fake a single golden
  match. Prove correctness with round-trip + known sub-component vectors + the
  parts you can compute by hand (#6).
- Cover each behavior with test-design viewpoints: equivalence partitioning,
  boundary values, encode/decode round-trip, and rejection of malformed input.

## Pick the right verification layer — don't mix, don't overuse

Three layers, three jobs (successes #1/#2). Decide the layer in planning, before
writing code:

- **State transitions / concurrency / protocol lifecycle → TLA+**
  (loop-engineering). Connection lifecycle, locks, queues, retries, ordering of
  reassembled input. Counterexamples become Gherkin acceptance specs.
- **Critical crypto / math properties → Lean 4** (formal-verification). Round-
  trip invertibility, encode==decode, soundness of input validation, exhaustive
  classification.
- **Everything else → TDD.** Test list first → Red (confirm it fails) → minimal
  Green → Refactor.

Properties proven in the top two layers become 1:1 predicates in the TDD test
list. Do NOT wire the layers together artificially, and do NOT apply TLA+/Lean
to trivial logic — that is over-engineering (YAGNI). No state and no concurrency
→ plain TDD is correct.

## Scope discipline

"Different RFC, so out of scope" is forbidden when the task is "implement
everything" (#9). A dependency RFC (e.g. QPACK / RFC 9204, TLS auth / RFC 8446)
is researched from the IETF source and implemented, not deferred. Large work is
split MECE and stacked in order — splitting is not scope exclusion. Do not
declare a self-chosen stopping point "done" while `[ ]` items remain.

## External verification tools may be blocked by the sandbox

Before planning verification through an external tool, confirm it actually runs
here (#23): the environment's `curl` lacked HTTP/3, `tcpdump` needs CAP_NET_RAW,
and `curl` itself was sandbox-denied — the whole planned path was dead. Make the
in-process / loopback-socket round-trip the FIRST-CHOICE verification, not a
fallback bolted on after the external path fails (#20/#23).

## A self-loopback green does NOT prove interoperability

The loopback round-trip above is the first-choice check for *your own*
correctness and libc independence. It is NOT the proof of spec compliance. A
self-loopback exercises one implementation talking to itself, so both ends share
the same code — and therefore the same bugs. A spec violation on both sides
cancels out and the test passes anyway (#28). This bit three times in one
push: the same wrong AEAD-key transcript, an unrecovered packet number, and a
reused-DCID mismatch each passed loopback yet broke a real peer.

- **Compliance can only be verified two ways**: (a) against the RFC's own known
  vectors, or (b) against an independent third-party implementation. "Our client
  talks to our server" means neither (#28/#18).
- **When the goal is interop, design from the peer's bytes, not from your own.**
  Implementing first and reconciling later surfaces incompatibilities one at a
  time, endlessly (#29). Enumerate the peer-facing MUST/SHOULD up front (apply
  the loop-engineering extraction pass to the interop requirements too).
- A test where one side is pinned to an RFC vector or a captured real-peer trace
  closes the loophole; two free sides that agree do not.
- **Completion condition**: any feature that touches the wire format stays `[ ]`
  (or `[~]`) in the ledger until such a pinned test exists. Loopback-green alone
  never flips it to `[x]` — three loopback-green wire bugs shipped before this
  rule existed (#28/#33).

## Reading the interop-runner's verdict

- Record PASS only when BOTH hold: the result row shows `✓` (check the letter
  code in parentheses — `?(E)` means UNSUPPORTED, not pass), AND the matching
  `logs_*/` directory for that run actually exists. An `?(E)` was once misread
  as a pass and recorded in two ledgers with no run log behind it (2026-07-20).
- Know the client's capabilities before blaming the server: the quic-go client
  does not support the ecn testcase (ngtcp2/picoquic do).
- Read the runner's own check logic (`testcases_quic.py` conditions) BEFORE
  implementing against a testcase — rebind-port took two implementation rounds
  that reading the checker first would have made one.

## Debugging an encrypted protocol against a real peer

Packet capture shows reachability, not meaning: an encrypted transport hides
which message or frame actually failed (#30). Use two instruments together:

- **The peer's own log is the fastest, surest oracle.** A real client's
  qlog / keylog (e.g. `QLOGDIR`, `SSLKEYLOGFILE`) reveals which packet it
  received, which CID it expects, how it parsed each frame, and the error/close
  code — the peer-side state a capture and your own logs cannot show (#16).
- **Stage the diagnostics by pipeline layer.** Emit a one-line ok/fail at each
  boundary (decrypt → stream-classify → frame → decode) so a single run pinpoints
  the layer that fails, instead of guessing and re-running (#17/#30). Dump the
  decrypted bytes once you can, to read the peer's actual wire format. These
  probes are temporary — remove them once the cause is found (see
  parallel-and-commit.md on diagnostic-trace hygiene).
- Rule out suspects by reading code against the RFC, one at a time, before
  reaching for a live trace: each "innocent" narrows the cause, and the live
  trace is the last resort, not the first (#14).
- **Cross-examine both ends before declaring a cause.** One side's log alone
  misleads: a server log was once read as "handshake failed, auto-retrying"
  when the client had simply been run four times by hand (2026-07-03). State a
  failure narrative only after your log and the peer's log agree on it.

## Test buffers must match production buffers

A test using `out[4096]` against production's `out[1500]` hid a 1750-byte
overflow: the unity suite stayed green while the real server broke. Any test
that exercises a size/boundary path uses the PRODUCTION buffer size — share the
constant (one `#define` both sides include), don't re-type the number. And when
a fixed-capacity buffer is widened, write the sizing rationale next to the
constant (max cert-chain length, BDP, ...): 10+ capacity bumps in this history
were reactive guesses, one of which SIGSEGV'd CI and was reverted within 7
minutes (#widen 07-19).

## A non-deterministic hang is usually undefined behavior

If `just test` (or any whole-suite run) hangs or fails to finish non-
deterministically — "sometimes passes, sometimes wedges" — suspect an
uninitialized variable first and run it under valgrind `--track-origins` (#35).
An uninitialized accumulator read as input made a scalar-multiply loop never
terminate. A blocker that breaks the verification itself gets the minimal fix
first, even if it is outside the task's scope.

## Honest progress ledgers

Keep a progress ledger split into what the SDK must implement vs. informational
items that are an operator / application / upper-layer concern and are NOT code
this SDK should ship (#13). Report the completion rate against the in-scope
denominator only; do not pad it by marking informational items done. Mark `[x]`
only what an implementation and a test actually demonstrate; when unsure, leave
`[~]`.
