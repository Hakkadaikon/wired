[Docs](../README.md) › [Features](README.md) › MoQT track switching

# MoQT track switching (experimental, moqtail-compatible)

The hub (`src/app/moqt/run/`) can switch a subscriber between variants of
one piece of media (for example a high- and a low-resolution copy of a
screen share) at a Group boundary. It does this in two ways, both taken from
[moqtail](https://github.com/moqtail/moqtail) (commit `ee9753c`) and wire-
compatible with it:

- **SWITCH_FROM** — the subscriber asks: "activate this subscription and
  stop that one".
- **SSTS** (sender-side track switching) — the subscriber puts both variants
  in a *switching set*, and the hub forwards one member per Group, picked by
  an algorithm.

**Status: experimental.** Neither mechanism is part of
draft-ietf-moq-transport-22. The code points below are unassigned there; the
values are moqtail's. Everything here works **on draft-22 sessions only**
and only when the hub enables it. With the hub flags off, or on a draft-18
or draft-19 session, parameters 0x24 and 0x41 still close the session with
PROTOCOL_VIOLATION, as they did before the extension
(`test_moqtrun_switch_off_closes`, `test_moqtrun_switch_old_drafts_close`,
`test_moqtrun_ssts_off_violates`). All verification so far is in-process
(loopback) plus codec vectors copied from moqtail-rs unit tests. **No
third-party implementation has been run against it yet.** See
[the draft-22 ledger](draft-moq-transport-22.md#experimental-extensions-moqtail-compatible-track-switching)
for the per-item status and
[Known Limitations](known-limitations.md#moqt-track-switching-experimental)
for the gaps.

Design and model: `tasks/moqt-trackswitch-plan.md` §1 (the wire contract)
and `tasks/loopeng/moqt/TrackSwitch/` (TLA+ models `TrackSwitch.tla` /
`SstsDecision.tla`, requirements TS-1..TS-10 and SS-1..SS-4). Neither is in
git.

## Wire format

All values use MOQT varints (vi). The two Message Parameters are
Length-prefixed (Type delta, Length, value), and each may appear in
SUBSCRIBE and in REQUEST_UPDATE of a subscription only
(`MOQCTL_PARAM_RULES` in `src/app/moqt/ctl/moqctl.c`).

| Code point | Kind | Value | Constant (`src/app/moqt/ctl/moqctl.h`) |
|---|---|---|---|
| 0x24 | Message Parameter SWITCH_FROM | Request ID (vi), Mode (vi: 0 Hard, 1 Soft), Flags (u8: 0x80 Publish Done, other bits must be 0) | `MOQCTL_PARAM_SWITCH_FROM`, `MOQCTL_SWITCH_HARD` / `_SOFT` |
| 0x41 | Message Parameter SWITCHING_SET_ASSIGNMENT | Set ID, Algorithm ID, Threshold kbps, Weight (1..10), Activate (all vi), optional Rank (u8) | `MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT` |
| 0x09 | Setup Option SSTS_ALGORITHMS (odd: Length + bytes) | concatenated algorithm-id varints, no count | `MOQCTL_OPT_SSTS_ALGORITHMS` |
| 0x32 | REQUEST_ERROR INVALID_SWITCH | a bad SWITCH_FROM | `MOQCTL_ERR_INVALID_SWITCH` |
| 0x33 | REQUEST_ERROR UNSUPPORTED_EXTENSION | an algorithm that was not negotiated, or a track already in another set | `MOQCTL_ERR_UNSUPPORTED_EXTENSION` |
| 0x3 | PUBLISH_DONE "switched" | the old subscription of a SWITCH_FROM with Publish Done | `MOQCTL_DONE_SWITCHED` |

Golden (`tests/app/moqctl_switch_test.c`, the same bytes as moqtail-rs
`test_switch_from_wire_format`): SWITCH_FROM for Request ID 7, Hard, Publish
Done is

```
24 03 07 00 80
```

That is Type delta 0x24, Length 3, Request ID 7, Mode 0 (Hard) and Flags
0x80. As a one-entry parameter list the bytes are `01 24 03 07 00 80`.

A value with trailing bytes, an unknown Mode, a Flags bit other than 0x80,
or a Weight outside 1..10 is a decode violation. A malformed SSTS_ALGORITHMS
option closes the session with KEY_VALUE_FORMATTING_ERROR.

0x32 is INVALID_JOINING_REQUEST_ID in draft-18/19, which is one reason the
extension is restricted to draft-22. 0x33 UNSUPPORTED_EXTENSION is a
standard code in all three drafts. PUBLISH_DONE 0x3 is written on its own
path (`moqtsw_done_code` in `src/app/moqt/run/moqtswitch.h`) and is not
remapped by `moqctl_publish_done_for`.

## SWITCH_FROM

Code: `src/app/moqt/run/moqtswitch.{h,c}`; tests:
`tests/app/moqtrun_switch_test.c`.

A SUBSCRIBE for track B (or a REQUEST_UPDATE of the subscription B)
carrying SWITCH_FROM {A's Request ID, Mode, Flags} activates B and stops
the same session's subscription A.

### Boundary rule

At accept time the hub computes

```
G = max(Largest_A.group, Largest_B.group) + 1     (0 when neither track has any Object)
```

A is bounded to end at Group G−1 and B to start at {G, 0}. The `+1` stops
a Group that is already open to the subscriber from arriving twice. Taking
the max with B avoids a gap when B is ahead. Both cases are TLC
counterexamples (`MC_bug_BoundaryNoPlus1`, `MC_bug_BoundaryOldOnly`). The
bounds only ever tighten, and they survive a publisher re-attach and a
LOCATION_FILTER update (`moqtsw_rebound`).

The variants must use the same Group numbers. The hub assumes this and does
not check it.

### Hard and Soft

- **Soft (Mode 1)**: A's streams are left alone. A ends once its track has
  reached G−1 and no A stream is still open. It also ends when
  `WIRED_MOQTSW_SOFT_WAIT_MS` (4000 ms) after the switch passes with no A
  stream open, in case A's publisher stalls.
- **Hard (Mode 0)**: A ends once B's group G (or a later one) reaches the
  hub, whether by stream or by datagram, or when B goes away (cancelled or
  ended). A's open streams are then reset with CANCELLED (0x1). If the
  hub cannot open B's group-G stream to the subscriber yet (no stream
  credit, or a backlog), A's in-flight groups are reset before B's group G
  arrives. The gap is explicit (a RESET), never silent. B's group G then
  arrives through a late open, so its first Object may be lost.
- G = 0 ends A at once in both modes.

How A ends depends on the Publish Done flag:

- **Flag 0x80 set**: A gets PUBLISH_DONE 0x3 ("switched") and its request
  stream FINs. A gets at most one PUBLISH_DONE, even when its publisher's
  TRACK_ENDED races the switch (`test_moqtrun_switch_done_once_track_ended`).
- **Flag clear**: A is *suspended*, as in moqtail. Its streams are reset,
  it gets FORWARD 0, and its request stream stays open with no
  PUBLISH_DONE. A later REQUEST_UPDATE on A carrying SWITCH_FROM of B
  switches back (`test_moqtrun_switch_back`).

### Refusals

The hub answers REQUEST_ERROR INVALID_SWITCH (0x32) and changes nothing
when:

- FORWARD is present.
- The Request ID names the request itself, or names no live subscription
  of the session.
- Both subscriptions are on the same track.
- A is already switching away.
- The target is one of the hub's own tracks.
- The REQUEST_UPDATE updates a PUBLISH.
- FILL_PARAMETERS is present (`test_moqtrun_switch_fill_refused`).
- The subscription is a member of an SSTS switching set.

## SSTS (sender-side track switching)

Code: the pure algorithms are in `src/app/moqt/ssts/moqssts.{h,c}` (prefix
`moqssts_`, ported from moqtail's `moqtail-ssts` crate). The hub side is in
`src/app/moqt/run/moqtssts_run.{h,c}`, with per-session state in
`moqtss.h`. Tests: `tests/app/moqssts_test.c`,
`tests/app/moqtrun_ssts_test.c`.

1. **Negotiation.** When the hub is configured, its draft-22 SETUP carries
   SSTS_ALGORITHMS. The session's algorithms are the intersection of the
   hub's list and the client's list.
2. **Membership.** A SUBSCRIBE (or REQUEST_UPDATE) carrying
   SWITCHING_SET_ASSIGNMENT puts that subscription into set Set ID.
   Members are kept sorted by Threshold. A set becomes active once it has
   `Activate` members. An algorithm the session did not negotiate, or a
   track that is already in another set, is refused UNSUPPORTED_EXTENSION
   (0x33). So is an assignment on a control-stream SUBSCRIBE or on a
   SUBSCRIBE to the hub's own tracks: only draft-22 request-stream
   subscriptions can join a set.
3. **Per-Group decision.** When the first stream or datagram of Group g of
   any member track reaches the hub, that set's decision for g is made by
   its algorithm (`moqtss_prime`). Each set keeps its own decisions, so
   sets whose publishers number Groups independently do not interfere.
   The decision is final for g and is never recomputed while g is within
   the set's newest Group minus 5. Only the chosen member's Group g is
   forwarded (`moqtss_sub_pass`, checked by the hub's normal per-Group
   gate). Fills and FETCH do not go through this gate.

### Algorithms

| ID | Name | Rule |
|---|---|---|
| 0 | default (`moqssts_default_decide`) | Splits the budget by strict Rank first, then by Weight within a Rank. Each set gets its highest member whose threshold fits its share, and a set that needs less than its share gives the rest back. The budget is the stricter of the subscriber connection's delivery-rate estimate (`io.est_kbps`, `wired_server_wt_est_kbps`: BBR's bottleneck bandwidth, else cwnd / smoothed RTT) and `ssts_cap_kbps`; unlimited when both are 0. |
| 0xff01 | backpressure (`moqssts_bp_decide`) | Measures depth: the subscriber streams the hub still holds open for one active set's member tracks, taking the deepest set (moqtail sums the sets, which keeps two sharers on the lowest tier). Every subscriber stream of the session that the hub reset since the last decision (busy shed, DELIVERY_TIMEOUT, reliable stall; `moqtss_note_shed`) counts as a timeout and adds to the depth. Resets count only while the session has a backpressure set. One tier is shared by all of the session's sets, and it starts at the lowest. The tier moves at each Group of the pacing set (the lowest-slot active backpressure set) and on the hub tick every 100 ms (`wired_moqt_tick`), so it keeps moving while that set is paused; other backpressure sets take the current tier clamped to their ladder. Depth ≤ 1 for 5 observations in a row moves up one tier. Depth ≥ 2 moves down one tier at once and starts a cooldown. During the cooldown, a timeout or 2 deeper decisions in a row move down again. |

The constants are in `src/app/moqt/ssts/moqssts.h`
(`MOQSSTS_DEPTH_TARGET`, `MOQSSTS_DOWNSHIFT_DEPTH`,
`MOQSSTS_UPSHIFT_GOP_STREAK`, `MOQSSTS_COOLDOWN_HIGH_STREAK`).

## Hub configuration

Every field is in `wired_moqt_hub` (`src/app/moqt/run/moqtrun.h`), and
`wired_moqt_init` sets each one to "off". Set them after `wired_moqt_init`:

| Field | Meaning |
|---|---|
| `switch_track` | 1 enables SWITCH_FROM on draft-22 sessions. |
| `ssts_algs`, `ssts_alg_n` | A caller-owned list of algorithm IDs to advertise (`MOQCTL_SSTS_ALG_DEFAULT` 0, `MOQCTL_SSTS_ALG_BACKPRESSURE` 0xff01). At most `MOQCTL_SSTS_MAX_ALGS` (4) are sent. `ssts_alg_n` 0 disables SSTS. |
| `ssts_cap_kbps` | A cap on the default algorithm's budget in kbps (the estimate is used when it is stricter). 0 means uncapped. |

```c
static const u64 algs[] = {MOQCTL_SSTS_ALG_BACKPRESSURE, MOQCTL_SSTS_ALG_DEFAULT};
wired_moqt_init(&hub, &io);
hub.switch_track = 1;
hub.ssts_algs    = algs;
hub.ssts_alg_n   = 2;
```

Capacity: each subscriber session can hold `WIRED_MOQTRUN_SSTS_SETS` (8)
switching sets (an assignment beyond that is refused INTERNAL_ERROR), and
each set can hold `MOQSSTS_MAX_MEMBERS` (4) members.
`WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` went from 3 to 4 so that one peer can
publish a fourth, low-rate variant track.

`examples/moqt_chat` uses all of this for its screen share. See
[its README](../../examples/moqt_chat/README.md#track-switching-screen-share-hilo-variants).

---

**Next:** [Known Limitations](known-limitations.md#moqt-track-switching-experimental)
([all features](README.md))
