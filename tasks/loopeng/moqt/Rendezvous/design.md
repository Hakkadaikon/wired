# Rendezvous in the wired hub: implementation design

Inputs: `extract.md` (rules R1-R9, testcase analysis) and `Rendezvous.tla`
(`RESULT.md`: no errors in `MC_main` / `MC_tight`; `MC_bug` reproduces the FIN
hazard). The read baseline is the main tree at `367ef23`. Line numbers below
refer to that baseline and will drift once moqtrun.c changes in the other
worktree, so re-grep the function names before editing.

## 1. Scope and what this does NOT fix

There are three gaps behind the interop failures in
`tasks/moqt-multidraft-ledger.md` l.240-250. The ledger currently treats them
as one.

| Gap | What | Unblocks |
|---|---|---|
| **R (this design)** | Hold a SUBSCRIBE with RENDEZVOUS_TIMEOUT > 0. Resolve it on PUBLISH, or expire it with TIMEOUT. | `rendezvous-timeout` (moq-rs) fully. The SUBSCRIBE_OK leg of all 9 `moq-test-*`. |
| **G1** | Relay SUBSCRIBE upstream to a PUBLISH_NAMESPACE publisher (d18/19 9.5, d22 7.6 MUST). The hub never originates a SUBSCRIBE. `moqtrun_route_peer_subscribe` only matches PUBLISHed tracks. | `announce-subscribe` (stitcher, aiomoqt), `subscribe-before-announce` (stitcher). Neither sends RENDEZVOUS_TIMEOUT. |
| **G2** | Relay the publisher's PUBLISH_DONE to downstream subscriptions, with each subscription's own stream count. Inbound PUBLISH_DONE is currently `moqtrun_dispatch_skip` (moqtrun.c:3963). | `publish-track-subscribe` and every `moq-test-*` (each checks PUBLISH_DONE TRACK_ENDED + stream_count, moqtest.rs:1001-1030). |

So **R alone flips exactly one runner case** (`rendezvous-timeout`). `moq-test-*`
needs R and G2. On top of that, the data plane must forward datagrams, EOG and
extensions unchanged and honor FORWARD=0. The ledger has not verified those.
The `moq-test` synthetic publisher is **client-side**: the moq-rs client is
both publisher and subscriber, and the relay needs no knowledge of the
`moq-test-00` tuple namespace.

R is built so that G1 plugs into it later (§5.8). The TLA+ model already covers
the G1 states (`upq`, stale upstream answers).

## 2. Where the pending state lives

New fixed-capacity table in the hub (`src/app/moqt/run/moqtrun.h`, next to
`fetches[]`):

```c
/** Fixed capacity: SUBSCRIBEs held for a publisher (RENDEZVOUS_TIMEOUT,
 * draft-18/19 10.2.6, draft-22 9.20.6), hub-wide. Each hold already pins
 * one request-stream slot (WIRED_MOQTRUN_MAX_REQS = 64), so 16 lets a
 * quarter of the pool wait at once -- interop clients hold one (moq-test-*,
 * rendezvous-timeout) or two (two subscribers of one track). Past it, or
 * past WIRED_MOQTRUN_RDV_PER_SESSION, the SUBSCRIBE is refused
 * EXCESSIVE_LOAD at once, never dropped. Each slot ~1.3 KB of BSS.
 * ponytail: room-sized; raise with WIRED_MOQTRUN_MAX_REQS. */
#define WIRED_MOQTRUN_MAX_RDV 16

/** Holds one session may own, so one session cannot take the whole table
 * (the WIRED_MOQTRUN_MAX_REQS_PER_SESSION pattern). */
#define WIRED_MOQTRUN_RDV_PER_SESSION (WIRED_MOQTRUN_MAX_RDV / 4)

/** Longest hold, ms: the relay MAY use a shorter timeout (10.2.6). Twice
 * the largest window a known interop client asks for (moq-rs moq-test:
 * 5000 ms; rendezvous-timeout: 500 ms), and short enough that an idle
 * subscriber cannot pin a request slot for longer than a page reload. */
#define WIRED_MOQTRUN_RDV_MAX_MS 10000

/** Retry Interval (ms + 1, draft-18 10.6: 1 = immediately) sent with the
 * EXCESSIVE_LOAD refusal of a hold that did not fit. */
#define WIRED_MOQTRUN_RDV_RETRY 1001

/** One SUBSCRIBE held for a publisher. Owner key is (wt, stream_id) --
 * never a pointer/index into hub->reqs[] (the fill-design owner_rid
 * pattern): the request slot is looked up again at resolve/expiry, so a
 * stream already gone simply ends the hold. */
typedef struct {
  int               in_use;
  wired_wt_session* wt;
  u64               stream_id;   /**< the SUBSCRIBE's request stream */
  u64               request_id;
  u64               deadline_ms; /**< wired_moqt_tick clock */
  /** The Full Track Name as moqtrun_key encodes it (WIRED_MOQTRUN_MAX_NS /
   * _MAX_NAME: a longer name is never held -- no PUBLISH can claim it). */
  u8  ns[WIRED_MOQTRUN_MAX_NS];
  usz ns_len;
  u8  name[WIRED_MOQTRUN_MAX_NAME];
  usz name_len;
  /** The SUBSCRIBE body as received, re-decoded (moqctl_subscribe_take,
   * the session's own draft) when the hold resolves: the decoded views
   * dangle after the dispatch. WIRED_MOQTRUN_CTL_MSG_MAX bounds every
   * body this hub accepts, so it always fits. */
  u8  body[WIRED_MOQTRUN_CTL_MSG_MAX];
  usz body_len;
} wired_moqtrun_rdv;
```

Hub field: `wired_moqtrun_rdv rdv[WIRED_MOQTRUN_MAX_RDV];` (wired_moqt_init
zeroes `in_use`). Freestanding memory is not zeroed, so init must clear every
slot. Run valgrind once after wiring, per build-and-verify.md.

Request-slot field, in `wired_moqtrun_req`:

```c
  /** 1 while this SUBSCRIBE is held for a publisher (hub->rdv): owed an
   * answer, so moqtrun_req_answered must not read kind && !live as
   * complete and FIN it (draft-19 3.3.2: no FIN before the response). */
  u8 rdv_held;
```

`moqtrun_req_answered` (moqtrun.c:~6190) becomes
`return q->kind && !q->live && !q->rdv_held;`. This is the fix the TLA+
mutation `MC_bug.cfg` demands. Without it a subscriber that FINs right after
SUBSCRIBE (d19 3.3.2 allows that) gets its stream ended with no answer.

Use a plain preceding `/** */` block for new members, not a trailing `/**<`
(build-and-verify.md fmt caveat). Keep joined lines at 79 columns or less.

## 3. Error code addition

`src/app/moqt/ctl/moqctl.h`: `#define MOQCTL_ERR_TIMEOUT 0x2ULL`. It is the
same value in d18 15.10.2, d19 15.11.2 and d22 16.11.2, so no
`MOQCTL_ERR_ROWS` mapping row and no `MOQVER_CAP_*` bit are needed.
`MOQCTL_ERR_EXCESSIVE_LOAD` (0x9) already exists and is the same in all three
drafts.

`moqtrun_send_request_error` (moqtrun.c:414) gains a sibling
`moqtrun_send_request_error_ri(p, code, retry)`, and the old function becomes
its `retry = 0` wrapper. Only the EXCESSIVE_LOAD refusal passes a Retry
Interval.

## 4. The timer hook

The hub already runs deadlines off `wired_moqt_tick(hub, now_ms)`
(moqtrun.c:4413). It stores the clock in `hub->live.last_now_ms`, which
`moqtrun_goaway_deadline` (6884) also uses. Expiry is checked by scanning in
`moqtrun_drain_tick` (`now_ms >= p->goaway_deadline`, 7032), and refused sends
retry on the next tick. In production `wired_srvrun_opt.on_step` calls the tick
on every loop step, and the loop polls at least every `SRVRUN_PTO_MS = 25` ms,
so expiry lands at most about 25 ms late. That fits inside the runner's 2 s
budget for a 500 ms window.

- Deadline at hold time: `hub->live.last_now_ms + u64_min(rt,
  WIRED_MOQTRUN_RDV_MAX_MS)` (`util/num.h u64_min`, already in tree).
- New `moqtrun_rdv_tick(hub, now_ms)` called from `wired_moqt_tick` **after**
  `moqtrun_drain_tick` and **before** `moqtrun_reqs_tick`. The TIMEOUT queued
  by the expiry is then flushed and FINned by `moqtrun_req_settle` in the same
  tick. This matches the model's atomic `Tick`.

## 5. Control flow

### 5.1 Arrival (`moqtrun_route_peer_subscribe`, moqtrun.c:1492)

Today: `if (!track) { DOES_NOT_EXIST; return; }`. The new path:

```
moqtrun_handle_subscribe(body) -> moqtrun_subscribe_checked(.., m, body)
  -> moqtrun_route_subscribe(.., m, body) -> moqtrun_route_peer_subscribe(.., m, body)
       track found  -> moqtrun_subscribe_peer_track (unchanged)
       not found    -> moqtrun_rdv_miss(hub, p, m, body)
```

`body` (the raw SUBSCRIBE body `moqtrun_handle_subscribe` already holds) is
threaded through as a new last parameter of these three static functions.
Re-encoding `m` with `moqctl_subscribe_encode` instead is **rejected**: the
encoder has no `ver`, and d22's typed LOCATION_FILTER
(`MOQVER_CAP_LOCFILTER_TYPED`) would not round-trip.

`moqtrun_rdv_miss`:
1. `rt = moqtrun_param_vi(moqctl_params_find(&m->params,
   MOQCTL_PARAM_RENDEZVOUS_TIMEOUT))`. Absent and 0 read the same (R9).
2. No hold, so DOES_NOT_EXIST at once (R8, existing behavior), when **any** of:
   rt == 0; `p->req == 0` (the legacy pre-d17 single-bidi control stream,
   where REQUEST_ERROR carries no Request ID and a deferred reply would be
   misattributed; R7 "MAY use a shorter timeout" covers this);
   `moqtrun_key_oversized(k)` (no PUBLISH can ever claim it).
3. Otherwise `moqtrun_rdv_admit`: a free slot, unless the table is full or the
   session already has `WIRED_MOQTRUN_RDV_PER_SESSION` holds. In those cases
   send **REQUEST_ERROR EXCESSIVE_LOAD with Retry Interval** at once. The TLA+
   `LOAD` path: explicit, never silent.
   - Alternative considered: DOES_NOT_EXIST, reading "relay clamps to 0" as
     R7+R8. That was rejected. EXCESSIVE_LOAD is truthful (10.6 "overloaded")
     and retryable.
4. Store wt, stream_id, request_id, deadline, key and body. Set
   `p->req->rdv_held = 1`. Send nothing.

Authorization and the reserved-namespace checks already ran in
`moqtrun_subscribe_checked`, so a refused SUBSCRIBE is never held (S17). The
hub's own blob and live tracks resolve in `moqtrun_route_subscribe` before the
peer route and are never held.

### 5.2 Resolve point: PUBLISH (`moqtrun_publish_checked`, moqtrun.c:867)

After `moqtrun_reattach_subs(hub, t, peer_idx, k)` and **before**
`moqtrun_queue_request_ok(p, 0)`, call `moqtrun_rdv_resolve(hub, t, k)`. For
each in-use slot whose key equals `k`, run `moqtrun_rdv_resolve_one`:
1. `sp = moqtrun_find_by_wt(hub, slot->wt)`,
   `q = moqtrun_req_find(hub, slot->wt, slot->stream_id)`. If either is
   missing, or `sp->closing` is set, free the slot and stop. The stream or
   session is already gone, which is the TLA+ `Cancel` path.
2. `saved = sp->req; sp->req = q;` then re-decode the body:
   `moqctl_subscribe_take(sp->ver, body, &off, &m)`.
3. `moqtrun_subscribe_peer_track(hub, sp, t, sp_idx, k, &m)`. This is the
   **unchanged** live-path function. It already handles every outcome:
   accept, the d18 DUPLICATE_SUBSCRIPTION versus d19/22 re-answer for a second
   hold of the same track by the same session (`moqtrun_sub_held_reply`), and
   subs[] full, which gives DOES_NOT_EXIST. That keeps exactly one answer.
4. `q->rdv_held = 0; sp->req = saved;` and free the slot.

The answer is queued on `q`. The `moqtrun_reqs_tick` at the end of the
publisher's dispatch (moqtrun.c:6313) flushes it.

Order matters in two ways:
- **Before PUBLISH_OK**, so the resolved subscriptions exist when the reply is
  built. Today the reply carries only LARGEST_OBJECT. If PUBLISH_OK later
  derives FORWARD from the downstream subscribers (d18/19 9.5 MUST "If at
  least one downstream subscriber has Forward State=1 ... use Forward State=1")
  it will see the held subscriber's FORWARD=0 (`moq-test-forward-zero`).
- **Before `moqtrun_subtracks_sync`.** d18/19 9.5 / d22 7.6 say "MUST proceed
  with the SUBSCRIBE and MUST NOT also forward the PUBLISH to that
  subscriber." Change `moqtrun_subtracks_candidate` (moqtrun.c:3538) to skip,
  and mark as tried, a SUBSCRIBE_TRACKS session that already holds an
  Established subscription on `t` (`moqtrun_track_sub_of_peer(t,
  st_peer_idx)`). The extra `||` goes into a predicate helper
  `moqtrun_subtracks_settled(st, t, slot, st_peer_idx)` so candidate stays at
  CCN 3. Review point: confirm that "tried with nothing sent" (no
  PUBLISH_SKIPPED) is right for d22, where PUBLISH_SKIPPED exists.

### 5.3 Expire path (`moqtrun_rdv_tick`)

For each in-use slot with `now_ms >= deadline_ms`, run `moqtrun_rdv_expire`:
the same target lookup as §5.2 step 1. Then `sp->req = q`,
`moqtrun_send_request_error(sp, MOQCTL_ERR_TIMEOUT)`, `q->rdv_held = 0`,
restore, and free the slot. The TIMEOUT has Retry Interval 0. This is R6. In
d22 the message is the same REQUEST_ERROR (0x05), which §1.5 calls
SUBSCRIBE_ERROR.

### 5.4 Cancellation paths

| Event | Hook | Action |
|---|---|---|
| RESET_STREAM or STOP_SENDING on the request stream | `moqtrun_req_cancel` (moqtrun.c:6658), reached from `wired_moqt_on_stream_reset`. That callback carries both, per moqtrun.h:1065. | Add `moqtrun_rdv_drop_stream(hub, p->wt, q->stream_id)`. The existing code already resets the hub's side with CANCELLED. No answer is sent (`NoSilentDrop`: cancelled means never answered). |
| Subscriber FIN | `moqtrun_req_note_fin`: no change. The hold continues (19 3.3.2). `rdv_held` keeps `moqtrun_req_settle` from ending it. | none |
| Subscriber session closes | `wired_moqt_on_session_close` (moqtrun.c:6610) | Add `moqtrun_rdv_drop_wt(hub, s)` **eagerly**. Lazy lookup failure is not enough, because a new session can reuse the same `wired_wt_session*` and the same client stream ids, and a stale hold would then answer the wrong request (S9). |
| Hub closes the session (`moqtrun_peer_close`, `closing = 1`) | §5.2/5.3 step 1 skip closing peers and free the slot. | The slot frees itself. |
| Publisher leaves before resolving | none | The hold is unaffected and keeps waiting (TLA+ `Leave`). |
| Hub GOAWAY to the subscriber | none | 10.4/9.2: "does not impact subscription state". An existing hold has a Request ID below the GOAWAY's (`peer_rid_next`), so it continues. At GOAWAY_TIMEOUT the session close drops it. |

### 5.5 Capacity full

See §5.1 step 3. One more case: a hold that resolves while the track's `subs[]`
is full gets the existing DOES_NOT_EXIST from
`moqtrun_subscribe_peer_track`. That is still exactly one answer.

### 5.6 REQUEST_UPDATE on a held SUBSCRIBE

d19 10.9 says the receiver "MUST respond with exactly one REQUEST_OK or
REQUEST_ERROR". The first response on the stream would read as the SUBSCRIBE's
answer. So at the top of `moqtrun_update_sub` (moqtrun.c:2815), call
`moqtrun_rdv_settle_early(hub, p)`. When `p->req->rdv_held` is set, it answers
the SUBSCRIBE with REQUEST_ERROR TIMEOUT now (R7: a shorter timeout is
allowed), clears the flag and frees the slot. The existing code then answers
the update with DOES_NOT_EXIST, because `moqtrun_upd_target` finds no
subscription. Each request gets exactly one answer, in order.

### 5.7 Version differences

There are none in rendezvous semantics (extract.md §0). Per-version effects
come only from existing machinery:
- d18: two holds by one session on one track resolve as SUBSCRIBE_OK plus
  DUPLICATE_SUBSCRIPTION (`MOQVER_CAP_DUP_SUBSCRIPTION`). d19/22: the second
  gets SUBSCRIBE_OK with the same alias.
- d18 FIN-cancel (`MOQVER_CAP_FIN_CANCEL_NS`) covers SUBSCRIBE_NAMESPACE and
  SUBSCRIBE_TRACKS only. A FIN on a held SUBSCRIBE never cancels it in any
  draft.
- d19 allows RENDEZVOUS_TIMEOUT on SUBSCRIBE_TRACKS (10.19.1). It is ignored
  there, because SUBSCRIBE_TRACKS already waits indefinitely.
- d22 says SUBSCRIBE_ERROR. It is the same encoder (`MOQCTL_T_REQUEST_ERROR`).

No new `MOQVER_CAP_*` bit.

### 5.8 G1 plug-in (later; the model already covers it)

When the hub learns to SUBSCRIBE upstream, add a `state` (HELD/UPQ) and
`up_wt`/`up_rid` to `wired_moqtrun_rdv`:
- A PUBLISH_NAMESPACE accept (`moqtrun_dispatch_publish_ns`), for each HELD
  slot under the namespace prefix: open an upstream SUBSCRIBE and move to UPQ
  (TLA+ `PublishNs`).
- An upstream SUBSCRIBE_OK moves the request into §5.2 resolution (`UpOk`).
- An upstream REQUEST_ERROR moves it back to HELD (`UpErr`, keeps waiting
  until the deadline).
- Expiry while in UPQ sends TIMEOUT downstream and resets the upstream stream
  CANCELLED. A late upstream answer for that rid is ignored (`up = "stale"`;
  `AtMostOneAnswer` proves no second reply).
- A SUBSCRIBE with rt = 0 that finds a namespace publisher goes upstream with
  no deadline. An upstream error then gives DOES_NOT_EXIST (`UpErr` with
  `dl = NoDl`).

## 6. CCN ≤ 3 function sketch (branch count noted)

| Function | Body | CCN |
|---|---|---|
| `moqtrun_rdv_rt(m)` | `return moqtrun_param_vi(moqctl_params_find(&m->params, MOQCTL_PARAM_RENDEZVOUS_TIMEOUT));` | 1 |
| `moqtrun_rdv_holdable(p, m, k)` | `return p->req && moqtrun_rdv_rt(m) && !moqtrun_key_oversized(k);` | 3 |
| `moqtrun_rdv_free_slot(hub)` | loop + `if (!in_use) return` | 3 |
| `moqtrun_rdv_owned(r, wt)` | `return r->in_use && r->wt == wt;` | 2 |
| `moqtrun_rdv_count(hub, wt)` | loop `n += owned` | 2 |
| `moqtrun_rdv_admit(hub, wt)` | `return count < PER_SESSION ? free_slot : 0;` | 2 |
| `moqtrun_rdv_store(slot, p, m, k, body)` | copies only (`bytes.h` put helpers, no new static copy loop) | 1 |
| `moqtrun_rdv_hold(hub, p, m, k, body)` | `slot = admit; if (!slot) { send_ri(LOAD); return; } store; p->req->rdv_held = 1;` | 2 |
| `moqtrun_rdv_miss(hub, p, m, k, body)` | `if (!holdable) { send(DNE); return; } hold(...)` | 2 |
| `moqtrun_rdv_key_eq(r, k)` | ns and name length+bytes via `ct_diffn`; put the `&&` chain in this helper | ≤3 (split into `_ns_eq`/`_name_eq` if needed) |
| `moqtrun_rdv_target(hub, r, &sp)` | `sp = find_by_wt; return sp && !sp->closing ? req_find(..) : 0;` | 3 |
| `moqtrun_rdv_answer(hub, r, fn, arg)` | the shared "lookup, swap `sp->req`, call fn, clear `rdv_held`, restore, free" step, with `fn` a function pointer (resolve or expire). `if (!q) { free; return; }` | 2 |
| `moqtrun_rdv_do_resolve(sp, q, r, t)` | re-decode + `moqtrun_subscribe_peer_track`; `if (take != OK) send(INTERNAL_ERROR)` | 2 |
| `moqtrun_rdv_do_expire(sp, q, r, _)` | `moqtrun_send_request_error(sp, MOQCTL_ERR_TIMEOUT)` | 1 |
| `moqtrun_rdv_resolve(hub, t, k)` | loop, `if (in_use && key_eq)` goes into a helper `moqtrun_rdv_matches(r,k)` | 3 |
| `moqtrun_rdv_due(r, now)` | `return r->in_use && now >= r->deadline_ms;` | 2 |
| `moqtrun_rdv_tick(hub, now)` | loop `if (due) answer(expire)` | 3 |
| `moqtrun_rdv_drop_stream(hub, wt, sid)` / `_drop_wt(hub, wt)` | loop `if (match) in_use = 0` (match predicate helper) | 3 |
| `moqtrun_rdv_settle_early(hub, p)` | `if (!p->req \|\| !p->req->rdv_held) return;` must go into a predicate helper `moqtrun_rdv_held_here(p)`, then answer(expire) through the slot found by stream | 2 |
| Modified: `moqtrun_req_answered` | `q->kind && !q->live && !q->rdv_held` | 3 |
| Modified: `moqtrun_subtracks_candidate` | `if (!t->in_use \|\| moqtrun_subtracks_settled(...)) return 0;` | 3 |
| Modified: `moqtrun_route_peer_subscribe`, `moqtrun_publish_checked`, `moqtrun_req_cancel`, `wired_moqt_on_session_close`, `wired_moqt_tick`, `moqtrun_update_sub` | one unconditional call each | unchanged |

`moqtrun_req_cancel` already has one `if` (CCN 2). Adding the call keeps it at 2.

## 7. Names: uniqueness check (grep run at 367ef23)

`grep -rn '<name>' src/ tests/ fuzz/` returned **0 hits** for each of: `rdv`,
`RDV`, `rendezvous` (other than `MOQCTL_PARAM_RENDEZVOUS_TIMEOUT`),
`MOQCTL_ERR_TIMEOUT`, `wired_moqtrun_rdv`, `held_sub`, `mrdv`,
`test_moqtrun_rdv`. `moqtrun_hold_*` is **taken** (pre-establishment replay
buffer, moqtrun.c:5963+), so the prefix is `rdv`, not `hold`. All new
functions are `static moqtrun_rdv_*`, the struct is `wired_moqtrun_rdv`, the
macros are `WIRED_MOQTRUN_{MAX_RDV,RDV_PER_SESSION,RDV_MAX_MS,RDV_RETRY}`, the
fields are `hub->rdv` and `wired_moqtrun_req.rdv_held`, and the test helpers
are `mrdv_*` in `tests/app/moqtrun_rdv_test.c`. Re-grep at implementation time,
because the other worktree may add names.

## 8. TDD test list (Gherkin; 1:1 with TLA+ invariants)

New `tests/app/moqtrun_rdv_test.c`, `test_moqtrun_rdv()`. Wire it into
`tests/run.c` with three edits (include, include test, call); the single
aggregation worker does that. Use the production constants
(`WIRED_MOQTRUN_RDV_MAX_MS`, `WIRED_MOQTRUN_MAX_RDV`) and never re-typed
numbers. Use the `moqtrun_sub_test.c` harness style (`mtst_*`) and drive the
clock with `wired_moqt_tick`.

| # | Invariant / witness | Scenario |
|---|---|---|
| S1 | `AtMostOneAnswer` | **Given** B SUBSCRIBEs (ns,t) with RENDEZVOUS_TIMEOUT 500 on a request stream and nobody publishes it **When** A PUBLISHes (ns,t) at clock 100 and the clock then passes 600 **Then** B's stream carries exactly one message, SUBSCRIBE_OK, and no REQUEST_ERROR. |
| S2 | `NoSilentDrop` + `CorrectCode` (TIMEOUT) / witness NoTimeoutAnswer | **Given** B holds with 500 at clock 0 **When** tick(499) **Then** nothing is sent **When** tick(500) **Then** REQUEST_ERROR code 0x2 is sent and the hub FINs B's stream after it. |
| S3 | `CorrectCode` (DNE), R8/R9 | **Given** no publisher **When** B SUBSCRIBEs with no parameter / with RENDEZVOUS_TIMEOUT 0 **Then** REQUEST_ERROR DOES_NOT_EXIST in the same dispatch and no slot is used. (`subscribe-error` regression.) |
| S4 | `ResolveOnPublish` / witness NoHeldThenOk | **Given** B holds **When** A PUBLISHes the same Full Track Name **Then** B gets SUBSCRIBE_OK with an alias and LARGEST_OBJECT (if any) on B's request stream, B is an active sub of A's track, and A gets its PUBLISH_OK **And** the slot is free. |
| S5 | witness NoTwoResolved | **Given** B and C both hold (ns,t) **When** A PUBLISHes **Then** both get SUBSCRIBE_OK, with distinct aliases. |
| S6 | `ClampOK` | **Given** B holds with RENDEZVOUS_TIMEOUT 60000 at clock 0 **When** tick(`WIRED_MOQTRUN_RDV_MAX_MS` - 1) **Then** nothing **When** tick(`WIRED_MOQTRUN_RDV_MAX_MS`) **Then** TIMEOUT. |
| S7 | `NoSilentDrop` (the MC_bug counterexample) | **Given** B holds **When** B FINs its side of the request stream **Then** the hub neither FINs nor resets the stream **And** (a) a later PUBLISH still yields SUBSCRIBE_OK, or (b) the deadline still yields TIMEOUT, followed by the hub's FIN. |
| S8 | `CancelClean` + `NoSilentDrop` (cancelled means never answered) | **Given** B holds **When** B RESET_STREAMs (or STOP_SENDINGs) the request stream **Then** the hub resets its side with CANCELLED, the slot is free, and a later PUBLISH or tick sends nothing on that stream id. |
| S9 | `CancelClean` (session) | **Given** B holds **When** B's session closes and a new session reusing the same `wired_wt_session*` opens a request stream with the same id **Then** a PUBLISH of (ns,t) sends nothing to the new session's stream. |
| S10 | `CapacityRespected` / witness NoLoadAnswer | **Given** `WIRED_MOQTRUN_RDV_PER_SESSION` holds from B **When** B sends one more **Then** it gets REQUEST_ERROR EXCESSIVE_LOAD with Retry Interval `WIRED_MOQTRUN_RDV_RETRY` at once, and the earlier holds are unaffected. Repeat hub-wide with `WIRED_MOQTRUN_MAX_RDV` across sessions. |
| S11 | `HeldHasDeadline` | **Given** a legacy single-bidi session (`p->req == 0`) **When** it SUBSCRIBEs with RENDEZVOUS_TIMEOUT 500 and no publisher **Then** it gets DOES_NOT_EXIST at once. |
| S12 | 9.5 MUST NOT also forward | **Given** C has SUBSCRIBE_TRACKS on prefix (ns) and also holds SUBSCRIBE (ns,t), and D has SUBSCRIBE_TRACKS on (ns) only **When** A PUBLISHes (ns,t) **Then** C gets SUBSCRIBE_OK and **no** hub-opened PUBLISH stream, and D gets one. |
| S13 | `AtMostOneAnswer` (update) | **Given** B holds **When** B sends REQUEST_UPDATE on the same stream **Then** in order: REQUEST_ERROR TIMEOUT (for the SUBSCRIBE), then REQUEST_ERROR DOES_NOT_EXIST (for the update), and a later PUBLISH sends nothing more. |
| S14 | version table | S2 and S4 under d18, d19 and d22 (TIMEOUT wire code is 0x2 in all). **Given** B holds the same (ns,t) twice in one session **When** A PUBLISHes **Then** d18: SUBSCRIBE_OK, then DUPLICATE_SUBSCRIPTION; d19/22: two SUBSCRIBE_OK with the same alias. |
| S15 | `Leave` / phase-1 limit | **Given** B holds **When** A sends PUBLISH_NAMESPACE (ns) only **Then** (until G1) B still gets TIMEOUT at the deadline. When G1 lands this flips to SUBSCRIBE_OK after the upstream SUBSCRIBE_OK. |
| S16 | GOAWAY | **Given** B holds **When** the hub GOAWAYs B's session and A PUBLISHes before the GOAWAY deadline **Then** B gets SUBSCRIBE_OK **When** instead the GOAWAY_TIMEOUT closes B first **Then** nothing is sent and the slot is free. |
| S17 | authorization | **Given** `authorize_subscribe` denies **When** B SUBSCRIBEs with 500 **Then** UNAUTHORIZED at once and no slot is used. |
| S18 | `AtMostOneAnswer` (d22 7.6 order) | **Given** B holds **When** A PUBLISHes and the same tick reaches the deadline **Then** only SUBSCRIBE_OK. Resolution happens in the dispatch, expiry only in the tick, so a resolved slot is already free. |

Gate per the rules: `just test-fast`, `just ninja`, `lizard src --CCN 3 -w`, and
the count check. Also run `just test` (single TU: the new `static` names), `just
docs` (new documented struct members), and `just fuzz-smoke` (the
`fuzz_moqt` harness drives the hub), plus valgrind once on the test binary.
Then re-run the moq-interop-runner `rendezvous-timeout` case with the
moq-rs-draft-18 client. A pinned peer, not loopback, is the completion
condition (rfc-and-verification-layers.md). Update `docs/features/draft-moq-
transport.md` (remove RENDEZVOUS_TIMEOUT from Out of scope at ~1314, add EARS
rows) and the MQ18/MQ22 ledgers in the same breath as the commit.

## 9. Ledger correction to carry over

`tasks/moqt-multidraft-ledger.md` l.249 expects rendezvous to fix aiomoqt's and
stitcher's `announce-subscribe`, stitcher's `subscribe-before-announce` and
moq-rs's `publish-track-subscribe`. Reading the clients does not support that.
None of those flows sends RENDEZVOUS_TIMEOUT. The first three need G1 and the
fourth needs G2. Record this when the ledger is next updated.
