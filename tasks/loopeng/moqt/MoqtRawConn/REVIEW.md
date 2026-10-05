# MoqtRawConn: independent review (ledger 13-2)

Reviewer pass, 2026-10-05. Inputs: `MoqtRawConn.tla`, `MC_*`, `EXTRACT.md`,
`RESULT.md`, `TRACE.md`, `counterexample.feature`, `wtroute/`; plan
`tasks/loopeng/moqt/RawQuic/plan.md` §1/§4/§5; specs
`tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt`; RFC 9000 §10.2; code
(read-only) `src/app/http3/server/{srvrun,srvloop}/`, `src/tls/ext/salpn/`,
`src/app/moqt/run/moqtrun.c` at HEAD `688c4af`.

## Verdict: **PASS** (with one model fix applied, and findings to carry into implementation)

No finding blocks the model's use as the S5 design gate. The one modelling gap
that could be fixed with a small edit (F1) was fixed and re-checked. The other
findings are documentation corrections, or design points for the
implementation phase (S9/S5) to absorb into TRACE/tests. None of them changes
a model verdict.

## 1. TLC re-runs (TLC2 2026.10.04, `-workers 1`)

Logs are in `logs/review/`.

| cfg | reported | re-run (original model) | result |
|-----|----------|-------------------------|--------|
| `MC_base` | 1,793,311 / 1,223,929 / depth 25, no error | 1,793,311 / 1,223,929 / depth 25 | **No error**, the 11 invariants and 2 liveness properties hold. Matches. |
| `MC_mut_late_session` | 11 / 9, SessBeforeData | 11 / 9 | Violated `SessBeforeData`. Matches. |
| `MC_mut_wt_path` | 20 / 18, PathRule | 20 / 18 | Violated `PathRule`. Matches. |
| `MC_mut_wt_path_live` | 41 / 37, EstablishLive | 41 / 37 | Violated `EstablishLive`. Matches. |
| `MC_mut_h3ctrl` | 3 / 3, NoH3OnRaw | 3 / 3 | Violated `NoH3OnRaw`. Matches. |
| `MC_mut_double_close` | 42 / 37, CloseOnce | 42 / 37 | Violated `CloseOnce`. Matches. |
| `MC_shipped_rawclose` | 36 / 27, NoDataAfterClose | 36 / 27 | Violated `NoDataAfterClose`. Matches. |

Re-runs after the F1 fix (the model as it now stands):

| cfg | result |
|-----|--------|
| `MC_base` (SetupOpts now 8 shapes) | 3,170,131 / 2,168,793 / depth 25, 7m40s: **No error**. All 11 invariants, `EstablishLive` and `CloseLive` hold. |
| `MC_mut_wt_path` (+BOTH) | 29 / 26: violated `PathRule` (still killed) |
| `MC_mut_wt_path_live` (+BOTH) | 61 / 55: violated `EstablishLive` (still killed) |

## 2. Non-vacuity of every invariant (check 1)

The authors' mutations kill 4 of the 11 invariants: SessBeforeData, PathRule,
NoH3OnRaw and CloseOnce, plus NoDataAfterClose via the shipped configs. The
`MC_reach_*` configs prove that the wanted behaviour is reachable, but they do
not prove that the remaining invariants can fail. I wrote one throw-away
mutant per invariant (scratch copies of the module; the repo model was not
changed for these). Each config uses one conn, offers from MC_base,
SetupOpts {NONE, BADPATH}, MaxData 2, and checks only the invariant named:

| mutant (edit) | invariant checked | result |
|---------------|-------------------|--------|
| v1: `DeliverGate` base branch → `conn[c] \in {"confirmed","closing"}` (no session/closing gate) | `NoGhost` | violated |
| v1 (same) | `NoDataAfterClose` | violated |
| v2: `ConnEnd` frees the slot without `CloseEv` | `CloseIffSession` | violated |
| v3: `DrainClose` chooses DrainWt for raw | `RawCloseShape` | violated |
| v4: raw session created on `alpn # "h3"` (hq gets one) | `SessOnlyOnApp` | violated |
| v5: `Goaway` gate `alpn # "hq-interop"` | `NoH3OnRaw` (the GOAWAY half, which the h3ctrl mutant does not reach) | violated |
| v6 (post-fix): `RawRule(REFAUTH) = 0` | `PathRule` | violated |
| original model, `CloseTearsDown = FALSE`, violations on | `SingleCloseFrame` alone | violated (261 distinct). This confirms that RESULT's "SingleCloseFrame shape" claim is a real violation, not just a trace observation. |

Conclusion: no invariant is vacuous. `TypeOK` is the only one that is
structural.

Traceability of EXTRACT ids to spec lines: every section and line anchor in
EXTRACT M1–M8 was checked against the spec files and is correct (d18 3.1.4
l.1373, 3.3 l.1465, 3.5 l.1664, 10.3.1.1 l.3554, 10.3.1.2 l.3571; d19 3.1.5
l.1432, 3.3 l.1525, 3.5 l.1762, 10.3.1.1 l.3890, 10.3.1.2 l.3907; d22 6.2.2
l.2505, 6.3 l.2525, 6.6 l.2818, 9.1.1 l.3930, 9.1.2 l.3947). Each id maps to
at least one invariant or property. The one exception was M5's unsupported
authority, which F1 fixes.

## 3. Findings

### F1 (Medium, FIXED): EXTRACT M5 "unsupported authority → INVALID_AUTHORITY" was not encoded, and the conforming raw client shape was missing

- The model had `REFPATH` but no `REFAUTH`. As a result, d22 §9.1.1 ("received
  by a server but the server does not support the specified authority … MUST
  be closed with INVALID_AUTHORITY"), which EXTRACT M5 cites, had no model
  element.
- The model had only single-option shapes. Plan §5.1 says SetupOpts are
  *subsets*. A conforming raw client for a `moqt://` URI MUST send **both**
  PATH and AUTHORITY (R8/R9), so the most important raw input was not
  explored. This is the shape that T-F2 tests.

**Fix applied** (`MoqtRawConn.tla`, marked `[review 2026-10-05]`):

- Two new option shapes:
  - `REFAUTH`: raw → 0x19 (25), WT → 0x19;
  - `BOTH`: raw → accept, WT → 0x8.
- `SpecVerdict`, `WtRule` and `RawRule` extended to match.
- `GoodSetup` now includes `BOTH`.
- `MC_base.cfg` SetupOpts now has 8 shapes. `MC_mut_wt_path[_live].cfg` add
  `BOTH`.
- Everything was re-checked as listed in §1.

Mixed-error combinations (for example BADPATH together with AUTH) are still
not modelled. Every option is checked independently in the spec text, and the
spec gives no ordering. Keep them in the TDD table (T-C*): any one of the
applicable codes is compliant.

### F2 (Low): `PathRule` on WT pins one of two compliant codes

For WT with a *malformed* PATH, both of these rules apply:

- "received while WebTransport is used" → INVALID_PATH 0x8;
- "does not conform" → MALFORMED_PATH 0x9.

`SpecVerdict` encodes only 0x8, and the same holds for BADAUTH (0x19 vs 0x1A).
This matches today's code and is a defensible choice, but it is an
implementation choice, not something the spec forces.

**Fix:** state it in EXTRACT as a decision ("WT check first"), or make the
oracle a set of allowed codes. T-C* should pin the chosen code with that
rationale.

### F3 (Low, documentation): two of the D2 call sites listed are not D2 instances

D2 itself is confirmed (see §4). However, RESULT.md, TRACE.md (`ViolationClose`
row) and counterexample.feature list `srvrun.c` 8922 and 10186 among the
closes that leave the connection up:

- **8922** (`srvrun_boot_give_up_close`) is followed immediately by
  `srvrun_note_ghost` and `srvrun_free_slot` (`srvrun.c:8930-8932`), so it
  does tear down at once.
- **10186** (`srvrun_close_drained`) runs once, after the shutdown drain, and
  then `srvrun_loop` returns (`10195-10205`). Nothing is delivered after it.
  (Side note: `wt_on_session_close` never fires for sessions still active at
  process shutdown. This is harmless because no storage is reused, but the hub
  gets no close callback at shutdown.)

The real D2 call sites are:

- `srvrun_close_on_bad_qsid` (2478);
- `srvrun_close_on_datagram_violation` (3868);
- `srvrun_close_on_wt_signal_violation` (3884);
- `srvrun_close_on_aead_limit` (3906);
- `srvrun_close_on_req_frame_error` (3918);
- `srvrun_close_on_reset_flood`, which seals and sends directly and bypasses
  `srvrun_send_app_close`.

The unified closing helper in TRACE must also cover the reset-flood path,
which never goes through `srvrun_send_app_close`.

**Fix:** correct the lists, and add the reset-flood path to the T-E14 rows.

### F4 (Medium, design point for S9/hub; outside the model's abstraction): hub-full session is silently orphaned

The model's `CreateSess` always succeeds at the hub. In code,
`wired_moqt_on_session` (`moqtrun.c:275-289`) does `if (!p) return;` when
`moqtrun_alloc` fails (`WIRED_MOQTRUN_MAX_SESSIONS` reached). The session then
stays active at srvrun, its deliveries are dropped by `moqtrun_find_by_wt`,
and nobody ever closes it. For raw this means a connection that never gets a
SETUP reply and is held until the 30 s idle sweep, where every client packet
restarts the idle timer. `EstablishLive` cannot see this, because it treats
the hub as unbounded. The same is already true on WT today.

**Fix:** the planned `wired_moqt_on_session_raw` must call
`io.close_session(s, INTERNAL_ERROR)`, or a dedicated code, when allocation
fails. On raw that becomes CONNECTION_CLOSE 0x1d via the latch, and the latch
works inside `raw_on_session` because TRACE sets `wt_active = 1` before the
callback. Add a test row next to T-F1. Optionally, model it as a
`HubFull(c)` branch of `CreateSess` that latches a close at once. Under the
current model, `CloseLive` would then cover it.

### F5 (Low): the model has no step atomicity, so D3 is outside what TLC checks

`WF_vars(Deliver(c))` lets delivery happen on any later step. In the code,
offer/deliver runs only inside `srvrun_on_step`, that is, only on a **peer
datagram**; ticks never deliver. The model therefore cannot tell the correct
placement of raw session creation (between `wired_srvloop_step` and
`srvrun_offer_wt_streams`) from the wrong one (in `srvrun_sess_on_step`, after
delivery). It also overstates liveness: an established-looking `Deliver`
may in reality wait for the client's next packet. In practice the client's ACK
of HANDSHAKE_DONE usually brings that packet, so the cost is latency, not a
deadlock.

The authors already record this as D3 and pin it with T-E12, which is the
right layer. Keep T-E12 mandatory.

**Optional model fix:** a `rx` flag set by a peer-datagram action. `Deliver`
requires it, and `Confirm`+`CreateSess`+`Deliver` share one step.

### F6 (Low): `NoGhost`/`CloseOnce` are per-connection, so one WT connection carries at most one session in this model

`WtConnect` requires `hub[c] = "none"`, so sequential or concurrent WT sessions
on one connection are not explored here. The `wtroute` side model covers them.
That is enough for raw (one implicit session per connection, never re-created).

**Fix:** state the restriction in EXTRACT ("one session per connection;
multi-session WT routing → `wtroute/`"), so nobody reads `MC_base` as covering
WT session churn.

### F7 (Low): D1 fix detail

The fix "pass `slot->wt_session_slot`" (RESULT D1 / TRACE `Deliver` row) is
right, but it has two edge cases:

- **The stream was never offered.** `offered == 0`, because no session was
  active at offer time. `wt_session_slot` then holds a stale or zeroed value,
  and the delivery must use `-1` (skip, as today) until the offer succeeds.
- **The owning session is gone.** Closing a session already resets and frees
  its streams (`srvrun_reset_wt_streams_for_session`, `srvrun.c:3339ff`), so a
  freed slot is never delivered. Even so, the delivery should also require
  `srvrun_wt_is_active(c, sidx)` as a guard.

**Fix:** use `sidx = slot->offered ? slot->wt_session_slot : -1` together with
the active check. Add the "offered later" row to T-E13. The `wtroute`
model's `own = -1` (not offered) case already blocks `Deliver`, which matches
this.

### F8 (Low, bookkeeping): the new tests are not yet in the plan

TRACE.md says "append to plan §7.5", but `plan.md` §7.5 still ends at T-E10.
T-E11 to T-E14 are not in it.

**Fix:** append them (and the F4 hub-full row to §7.6) when the plan is next
edited.

## 4. Real-code discrepancies (check 4)

- **D1: confirmed.** The bidi and uni offers set
  `slot->wt_session_slot = sidx` (`srvrun.c:2322`, `2652`).
  `srvrun_offer_and_deliver_wt_slot` (`2456`) and `_uni_slot` (`2682`) then
  recompute `sidx = srvrun_wt_slot_for_new_stream(c)`, which is the first
  active slot. Two sessions can be active only with WT flow control on
  (`srvrun_wt_single_session_full`, `2218`), and a later CONNECT fills the
  lowest free slot (`srvrun_wt_free_slot_any`). So the wtroute trace (A in 0,
  B in 1, A closes, x offered to B, C takes 0, x delivered to C) is reachable.
  This does not occur on raw (one session).
- **D2: confirmed.**
  - `srvrun_send_app_close` (`2038-2046`) and `srvrun_send_transport_close`
    (`2141-2149`) only seal and send.
  - srvrun/srvloop have no closing latch: `c->l.peer_closed` exists only for
    the *peer's* close (`srvrun_send_step_reply`).
  - After a violation close, `srvrun_on_step` returns early for that step
    only. The violation latches are consumed, `c->up` stays 1, and the next
    datagram runs the full offer/deliver/pump path again (`4050-4086`).
  - `wt_on_session_close` comes only from `srvrun_free_slot` →
    `srvrun_close_all_wt` (`5715-5717`).
  - Two caveats, see F3: two of the listed call sites are mis-attributed, and
    the reset-flood close is an extra D2 call site.
- **D4: confirmed.** `negotiate.c:78` walks the client list. The
  `negotiate.h:32` and `sdrv.c:420` comments are stale.
- **Holding today: confirmed.**
  - `srvrun_close_wt_session_slot` notifies, then clears `active`
    (`3366-3383`).
  - `srvrun_free_slot` calls `close_all_wt` before `conntable_remove`.
  - The SETTINGS gate is `== SALPN_H3`.

## 5. Interleavings (check 2)

- **Data in the same datagram as Finished.** The model allows `PeerStream` in
  `hs`, followed by `Confirm` and then `Deliver`. `SessBeforeData` covers the
  ordering. Same-step delivery is out of scope (F5), and T-E12 pins it.
- **Close racing with delivery.** Covered:
  - `Deliver` can interleave between a hub latch (`HubClose` or verdict) and
    `DrainClose`, which matches the code: deliveries in the same step precede
    `srvrun_drain_wt_close_pending`.
  - A `ViolationClose` before or after `DrainClose` is explored. In the
    design, `closing` disables the second close, which is how
    `SingleCloseFrame` holds.
  - In the code both run in the same `srvrun_on_step`: the drain first, then
    `srvrun_close_on_step_violation`. So the planned `c->closing` check must
    also gate `srvrun_close_on_step_violation`, including reset flood. TRACE's
    "every later close is a no-op" already says this. Make sure the test
    covers the same-step order.
- **Peer CONNECTION_CLOSE in the same datagram as a hub close.** `ConnEnd` is
  atomic and the model has no draining state. RFC 9000 §10.2.2 allows one
  CONNECTION_CLOSE in reply, so a raw close sent in that step is compliant.
  Not a finding.
- **Slot reuse.** One slot is shared by two attempts, and `ClientHello`
  requires `slot = None`. This is the worst case for pointer reuse, and
  `NoGhost` plus `CloseIffSession` are non-vacuous (§2).

## 6. Liveness and fairness (check 3)

- **Fairness.** WF is on Confirm, Deliver, DrainClose and RawCreateLate. The
  environment actions are *not* fair: PeerStream, ConnEnd, ViolationClose and
  ClientHello. This is the right split: server-internal progress is fair, and
  peer, idle and violation events are adversarial.
- **`EstablishLive` is not trivial.**
  - The premise requires `sent >= 1` and `confirmed`.
  - The escape clause (`hubErr = NoCode` with closing or gone) only admits
    outside ends, never a hub verdict error.
  - `mut_wt_path_live` violates it, and so does the post-fix version with
    `BOTH`.
- **`CloseLive` is not trivial.** `shipped_appclose_live` violates it.
- **Caveat.** Deliver fairness abstracts "needs a peer datagram" (F5).

## 7. TRACE coverage (check 5)

- **Actions.** All 11 actions (ClientHello, Confirm, RawCreateLate, WtConnect,
  PeerStream, Deliver, HubClose, DrainClose (Raw/Wt), ViolationClose, Goaway,
  ConnEnd) map to a planned function and a test id.
- **Properties.** All 11 invariants and both liveness properties have an
  "enforced by" entry and a test.
- **Gaps.**
  - F3: correct the list of close call sites and add reset flood.
  - F4: add the hub-full row.
  - F8: copy T-E11 to T-E14 into plan §7.5.

## 8. Files changed by this review

- `MoqtRawConn.tla`: F1 (the REFAUTH/BOTH shapes, oracle and rules,
  `GoodSetup`).
- `MC_base.cfg`, `MC_mut_wt_path.cfg`, `MC_mut_wt_path_live.cfg`: the
  SetupOpts additions.
- `logs/review/`: all re-run and vacuity logs (`rerun_orig_*`, `postfix_*`,
  `vac_*`).
- `REVIEW.md`: this file.
