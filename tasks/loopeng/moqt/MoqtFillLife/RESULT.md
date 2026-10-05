# MoqtFillLife: TLC results (ledger 7-1 (b))

TLC2 2026.10.04 was run with `-workers 1`. Logs are in `logs/<cfg>.out`. Code was
read at HEAD `206c185`. The earlier `tasks/loopeng/moqt/MoqtFill/` work is not in
this checkout, so this model was written from scratch.

## Invariants and properties

**Safety invariants:**

| invariant | requirement |
|-----------|-------------|
| `TypeOK` | — |
| `FillRangeSpec` | F2/F3: the range the hub serves equals the spec range, and a stream exists exactly when that range is non-empty (for an unpaused request). |
| `PausedNoFill` | F5 |
| `NoSilentDrop` | F7: no accepted fill is dropped. |
| `CancelResets` | F6 |
| `MalformedCloses` | F10 |
| `DoneCountExact` | F9: the count equals the fill streams opened, and PUBLISH_DONE never goes out while a counted fill is unopened. |

**Liveness under weak fairness:**

- `FillsEnd`: a held or waiting fill eventually opens, ends, or is freed by a cancel.
- `DoneEventually`

## Runs

| cfg | constants | states generated / distinct / depth | result |
|-----|-----------|-------------------------------------|--------|
| `MC_base1` | Subs={s1}; sub filters none, next, abs1 × fill filters absent, 0x00, abs0, absPast; MaxUpd=1; Slots=2, Waits=1 | 2,918 / 2,186 / 9 | **No error.** 7 invariants and 2 liveness properties hold. |
| `MC_base2` | Subs={s1,s2}; abs1 × {absent, abs0}; Slots=1, Waits=3 (contention through `fetch_waits`) | 37,115 / 18,751 / 16 | **No error.** |
| `MC_omitted` | fill filter *omitted*, all sub filters | 6 / 6 / 2 | **Violated:** `FillRangeSpec` (F-B1). |
| `MC_omitted_abs` | fill filter omitted, sub filter AbsoluteStart{1} | 3 / 3 / 2 | **Violated:** `FillRangeSpec` (F-B1, second shape). |
| `MC_malformed` | malformed FILL_PARAMETERS | 2 / 2 / 2 | **Violated:** `MalformedCloses` (F-B2). |
| `MC_capacity` | Slots=1, Waits=0, two fills | 14 / 14 / 3 | **Violated:** `NoSilentDrop` (F-B3, the ruled capacity boundary). |
| `MC_mut_cancel` | mutation: a cancel leaves fills alone | 11 / 11 / 3 | Violated `CancelResets`; the mutation is killed. |
| `MC_mut_done` | mutation: PUBLISH_DONE is not deferred | 35 / 33 / 4 | Violated `DoneCountExact`; the mutation is killed. |

An earlier attempt with Subs={s1,s2} and every filter combination grew past 1.7M distinct states and was stopped. It was split into base1 and base2.

## Findings

### F-B1 (real): an omitted LOCATION_FILTER inside FILL_PARAMETERS is treated as "whole track"

Spec §3.4 says to use the subscription's Location filter instead. Two traces show the effect:

- `logs/omitted.out`: the SUBSCRIBE has filter NextObject (0x05) with FILL_PARAMETERS but no LOCATION_FILTER. The spec range, NextObject evaluated as a Fetch, starts after Largest, so **no** fill stream should open. The hub opens a fill over groups 0..Largest.
- `logs/omitted_abs.out`: with AbsoluteStart{1,0}, the spec range is groups 1..Largest. The hub serves 0..Largest.

Code: `moqfetch_fill_filter_of` (moqfetch.c:285) folds "absent" into `has_filter=0`, and `moqtrun_fill_rl` (moqtrun.c:2342) maps that to the whole track. The subscription's filter is never consulted. Ruling Q-02 covers only 0x00 and zero-length, not omission.

### F-B2 (real): a malformed FILL_PARAMETERS value is silently ignored after SUBSCRIBE_OK

`moqtrun_fill_from_param` returns at moqtrun.c:2391 without closing the session. SUBSCRIBE_OK has already been queued (:1407). The spec requires PROTOCOL_VIOLATION (§9.20.15 with §9.20 l.5084-5087). Example: FILL_PARAMETERS carrying an unknown inner parameter type, or a truncated LOCATION_FILTER.

### F-B3 (ruled, recorded for the coordinator)

When `fetches[]` and `fetch_waits[]` are both full, `moqtrun_fill_wait_put` returns at :2307. The fill is never opened and never reset, which violates §3.4.1 "MUST open a fill fetch stream and reset it".

The 2026-10-04 ruling approved this on the premise that the request "has no slot at acceptance time". The trace shows that premise does not hold: SUBSCRIBE_OK (:1407) or REQUEST_OK (:2830) has already been queued before the fill is placed. The subscriber therefore holds an accepted fill that never arrives and has no signal.

Two fixes would satisfy the model:

- Count capacity before replying, and refuse with REQUEST_ERROR.
- Keep a "failed" fill record so that it is opened and reset INTERNAL_ERROR (the same shape as `failed`).

### Holds as modeled

The following all hold: pausing via FORWARD 0, a REQUEST_UPDATE without FILL opening nothing, FETCH_HEADER Request ID per message, cancel reset, open-then-reset on upstream loss, held fills converting from `fetch_waits`, deferred PUBLISH_DONE with an exact fill Stream Count, and liveness of every placed fill.

### Observation (not modelled as a violation)

`moqtrun_track_retire` (:791) drops the track cache while fills of that `cache_tag` keep serving. This happens when a PUBLISH stream is reset or a name is superseded. The fill then ends with an End-of-Timed-Out-Range marker and FIN, instead of the INTERNAL_ERROR reset that Q-08 prescribes for upstream failure (`moqtrun_fills_upstream_gone` is called only from `wired_moqt_on_session_close`). §3.2 permits a Timed-Out gap, so this is a Q-08 consistency question rather than a spec violation.
