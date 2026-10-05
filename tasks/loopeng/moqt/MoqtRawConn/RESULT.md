# MoqtRawConn: TLC results (ledger 13-2, plan S0b)

**Run setup:**

- TLC2 2026.10.04 with `-workers 1`.
- Logs are in `logs/<cfg>.out` and `wtroute/logs/<cfg>.out`.
- Code was read at HEAD `7e7a0dd` (main tree, read-only).
- Spec texts are `tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt`.
- RFC 9000 §10.2 and §10.2.1 were read from the rfc-editor.org text on
  2026-10-05.

**Files:**

- `EXTRACT.md`: MUST/SHOULD list, variables and code anchors.
- `MoqtRawConn.tla`: the model.
- `MC_*.tla`/`.cfg`: model-checking configurations.
- `counterexample.feature`: Gherkin specs derived from the traces.
- `TRACE.md`: model-to-code trace table (plan S5).
- `wtroute/`: side model for D1.

**Status:** reviewer pass done 2026-10-05: **PASS**, see `REVIEW.md`. The
reviewer added the REFAUTH/BOTH setup shapes (F1). Post-fix `MC_base`:
3,170,131 / 2,168,793 / depth 25, no error (`logs/review/postfix_base.out`).
The table below shows the pre-fix numbers.

## Properties

### Safety invariants

| invariant | requirement (EXTRACT id) |
|-----------|--------------------------|
| `TypeOK` | — |
| `SessBeforeData` | A2, M4: no `data` event before that connection's `session` event |
| `CloseOnce` | A1: `on_session_close` fires at most once per session |
| `CloseIffSession` | A1: a gone connection whose session was announced has had its close; no close without a session |
| `NoGhost` | A1: no data after the owner's close, and slot reuse (the next `session`) only after the previous owner's close |
| `NoH3OnRaw` | M8: no H3 control/SETTINGS/GOAWAY on raw |
| `RawCloseShape` | M7: hub close is `CONNECTION_CLOSE`(MoQT code) only on raw and `CLOSE_WT` only on WT |
| `PathRule` | M5, M6: every hub verdict equals the spec table (`SpecVerdict`) |
| `NoDataAfterClose` | Q1: no app delivery after the server sent CONNECTION_CLOSE |
| `SingleCloseFrame` | Q2: at most one CONNECTION_CLOSE (one code) per connection |
| `SessOnlyOnApp` | M2: no session for hq-interop or a failed ALPN |

### Liveness (weak fairness on Confirm, Deliver, DrainClose; peer close and idle are NOT fair)

- `EstablishLive` (L1): a raw connection whose client sent a well-formed,
  supported SETUP reaches Established, unless the connection ends for an
  outside reason with no hub error.
- `CloseLive` (L2): a hub close request always ends in `on_session_close`,
  without waiting for the peer or the idle sweep.

The plan's second liveness, "gone ~> close", is atomic in this model
(`srvrun_free_slot` notifies in the same action), so it is checked as the
safety `CloseIffSession`. The liveness slot goes to `CloseLive`, which is the
part that can actually fail.

## Runs

| cfg | constants | generated / distinct / depth | time | result |
|-----|-----------|------------------------------|------|--------|
| `MC_base` | Conns={c1,c2} on one slot; offers `[moqt-18,h3]`, `[h3,moqt-22]`, `[hq-interop]`, `[moqt-16]`, `[moq-00,moqt-19]`; RawList={18,19,22}; SetupOpts=all 6; MaxData=2; design switches | 1,793,311 / 1,223,929 / 25 | 3m56s | **No error.** 11 invariants and 2 liveness properties hold. |
| `MC_mut_late_session` | raw, PATH, MaxData=1, `MutLateSession` | 11 / 9 / 4 | 1s | **Violated `SessBeforeData`.** Mutation killed. |
| `MC_mut_wt_path` | raw, {PATH, AUTH}, `MutWtPath` | 20 / 18 / 5 | 1s | **Violated `PathRule`.** Killed. |
| `MC_mut_wt_path_live` | same, liveness only | 41 / 37 / 7 | 1s | **Violated `EstablishLive`.** Killed. This reproduces REQ-B. |
| `MC_mut_h3ctrl` | raw, `MutH3Gate` | 3 / 3 / 3 | 1s | **Violated `NoH3OnRaw`.** Killed. |
| `MC_mut_double_close` | raw, {NONE, BADPATH}, `MutKeepActive` | 42 / 37 / 7 | 1s | **Violated `CloseOnce`.** Killed. |
| `MC_shipped_rawclose` | raw, NONE, MaxData=2, `CloseTearsDown=FALSE`, no violation closes (the plan-S5 raw close built on today's `srvrun_send_app_close`) | 36 / 27 / 9 | 1s | **Violated `NoDataAfterClose`.** This is D2. |
| `MC_shipped_appclose` | raw and WT offers, `CloseTearsDown=FALSE`, violation closes on | 108 / 86 / 6 | 1s | **Violated `NoDataAfterClose`.** This is D2 on the existing violation-close path. |
| `MC_shipped_appclose_live` | raw, `CloseTearsDown=FALSE`, liveness only | 60 / 52 / 9 | 1s | **Violated `CloseLive`.** This is D2. The same trace also has two different close frames (`CCX` then `<<CC,9>>`), which is the `SingleCloseFrame` shape. |
| `MC_reach_*` (6 configs) | non-vacuity, 2 conns, 3 offers, 3 opts | ≤ 6,163 / 5,083 / ≤ 7 | ≤ 2s each | **Every one violated, as intended.** The base model reaches all of these: raw Established, WT Established, slot reuse by c2 after c1, raw close 0x9 then gone, WT close 0x8, and a full raw session→data→close lifecycle. |
| `wtroute/MC_shipped` | Sess={A,B,C}, 2 slots, 1 stream, 2 chunks, `RouteByOwner=FALSE` | 263 / 164 / 7 | <1s | **Violated `DeliverToOwner`.** This is D1. |
| `wtroute/MC_fixed` | same, `RouteByOwner=TRUE` | 592 / 284 / 10 | <1s | **No error.** |

## Mutations (all 4 required ones killed)

| mutation | code shape it stands for | trace (shortest) | killed by |
|----------|--------------------------|------------------|-----------|
| late_session | raw stream routed to `wt_on_stream_data` without the `sidx >= 0` gate; session made later in `srvrun_sess_on_step` | ClientHello(moqt-18) → PeerStream → Deliver (still in `hs`, no session) | `SessBeforeData` |
| wt_path | hub keeps `moqtrun_setup_opt_bad` for raw | Confirm → PeerStream(PATH) → Deliver ⇒ latch 0x8 | `PathRule`; liveness: … → ConnEnd with hubErr 0x8, never Established (`EstablishLive`) |
| h3ctrl | `build_settings_frame` gate `!= SALPN_HQ` | ClientHello(moqt-18) → Confirm emits H3CTRL | `NoH3OnRaw` |
| double_close | raw close notifies but leaves `wt_active=1`; `srvrun_close_all_wt` notifies again | Deliver(BADPATH) ⇒ latch 9 → DrainClose (CC 9, close #1) → ConnEnd (close #2) | `CloseOnce` |

## Findings in the current code

### D1 (real, WT path): stream bytes are delivered to the first active session, not to the session the stream was offered to

**Where:**

- The offer records the owner: `srvrun_offer_wt_slot` (`srvrun.c:2312`) and
  `srvrun_offer_wt_uni_slot` (`srvrun.c:2642`) set `slot->wt_session_slot`
  to the first active slot.
- Each delivery then recomputes `sidx = srvrun_wt_slot_for_new_stream(c)`
  instead of using that field: `srvrun_offer_and_deliver_wt_slot`
  (`srvrun.c:2456`) and `srvrun_offer_and_deliver_wt_uni_slot`
  (`srvrun.c:2682`).

**How it shows up:** with WT flow control on, two sessions may be open
(`srvrun_wt_free_slot`). The trace in `wtroute/logs/shipped.out`:

1. Session A is opened in slot 0 and session B in slot 1.
2. A closes.
3. Stream x is offered and associated with B (slot 1).
4. A new CONNECT establishes C in slot 0. This happens in
   `srvrun_sess_on_step`, after the same step's deliveries.
5. The next chunk of x is delivered with **C's** session pointer.

The hub (`moqtrun_find_by_wt`) then treats B's bytes as a new stream of C.
Closing B later resets x by its owner slot, while C has already consumed part
of it.

**Fix:** pass `slot->wt_session_slot` to the delivery. The `wtroute` fixed
config verifies this.

**Raw impact:** a raw connection has exactly one session (slot 0), so this
does not occur on raw. The raw path does call the same functions, so the fix
belongs in the shared code. Test T-E13 (new).

### D2 (real, WT today, carries over to raw by plan S5): a server CONNECTION_CLOSE does not end the connection

**Where:** `srvrun_send_app_close` (`srvrun.c:2038`) and
`srvrun_send_transport_close` only seal and send the frame. No closing state
exists anywhere in srvrun/srvloop (grep: no `closing`/`close_sent` latch).

**What happens:** the connection stays `up`, its WT sessions stay active, and
each later peer datagram still runs `srvrun_on_step`. That means:

- offer/deliver: `wt_on_stream_data` to the app;
- the capsule pass;
- the pump, which keeps sending STREAM frames from `wtsend[]`.

`wt_on_session_close` fires only at `srvrun_free_slot`. That happens at a
peer CONNECTION_CLOSE or at the idle sweep (`WIRED_SRVRUN_IDLE_MS` 30 s,
restarted by every received packet).

**Spec conflict:** RFC 9000 §10.2 says "A CONNECTION_CLOSE frame causes all
streams to immediately become closed … After sending a CONNECTION_CLOSE frame,
an endpoint immediately enters the closing state", and §10.2.1 says it retains
only enough state to resend CONNECTION_CLOSE.

**Today's WT callers** (all violation closes):

- bad qsid, `srvrun.c:2478`;
- H3_FRAME_ERROR, `3884` / `3918`;
- AEAD limit;
- reset flood;
- shutdown drain, `10186`.

**Raw impact:** plan S5 says the raw close is "`srvrun_send_app_close(code,
reason)`, then the existing teardown fires `wt_on_session_close` once". No such
teardown exists on that path. Built as written, the raw close:

- keeps delivering to a hub peer that is already `closing`;
  `MC_shipped_rawclose` shows the data after `<<CC,0>>`;
- holds the hub's peer slot (`WIRED_MOQTRUN_MAX_SESSIONS`) until the
  idle/peer close, which is what `CloseLive` fails on;
- can put a second, different close code on the wire when a violation close
  and a hub close coincide (`SingleCloseFrame` shape, seen in the
  `shipped_appclose_live` trace).

**Fix** (TRACE.md):

- add a `c->closing` latch, set by every CONNECTION_CLOSE sender;
- skip offer/deliver/pump/send while it is set, except for resending the
  identical close frame;
- close every active session (notify, then `active = 0`) in the same step;
- reap after 3×PTO.

The model with `CloseTearsDown=TRUE` (`MC_base`) is exactly this design and is
clean. Tests T-E14 (new) and T-E8.

Some of these are code-read facts that the model abstracts away rather than
checks: that the pump keeps sending STREAM frames after the close, and that
the idle timer restarts on every packet.

### D3 (design note, not a violation)

Today's WT session start (`srvrun_start_wt`) runs in `srvrun_sess_on_step`,
after the deliveries in `srvrun_on_step`. If the raw session is created in the
same place, `SessBeforeData` still holds: the bytes stay buffered in the slot
table. But bytes that arrived in the confirming datagram (client Finished
coalesced with the 1-RTT SETUP) are delivered only when the **next** peer
datagram arrives, because tick paths never run offer/deliver.

The plan already says "before the stream-delta delivery of that step". TRACE.md
pins the exact position: between `wired_srvloop_step` and
`srvrun_offer_wt_streams`. Test T-E12 (new).

### D4 (doc only)

`negotiate.h` (`salpn_negotiate` doc: "server's fixed preference order -- h3
first") and `sdrv.c:420` ("preferring h3 over hq-interop") are stale.
`negotiate.c:78` walks the **client** list, which is what R5 needs. Fix them
when S6 touches the file.

### Checked and holding in today's code

The model holds for the following WT behaviour as it exists today:

- `srvrun_close_wt_session_slot` and `srvrun_close_all_wt` notify then clear
  `active`, so a session gets one close;
- `srvrun_free_slot` notifies before `conntable_remove`, and
  `srvrun_open_slot` zeroes the conn, so there is no ghost on reuse;
- the pointer lookup requires `up && active`;
- the `wt_close_pending` latch is cleared before the active check
  (`srvrun_drain_wt_close_one`);
- the SETTINGS and GOAWAY gates are `== SALPN_H3`.

One residual hazard was considered and not modelled. An app that calls
`wired_server_wt_close_session` from **inside** `wt_on_session_close` on the
`srvrun_send_wt_close` path re-latches `wt_close_pending[sidx]` after it was
cleared. A later session in the same slot would then be closed with the stale
code. The hub never does this (`wired_moqt_on_session_close`, `moqtrun.c:6804`),
so it is recorded here, not counted as a finding.
