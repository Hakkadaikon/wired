# MoqtFillLife: requirements and variables (ledger 7-1 (b), item 4-6)

Spec: `tasks/specs/draft-ietf-moq-transport-22.txt`. Code was read at HEAD `206c185`.

## Spec requirements (draft-22)

| id | level | text (section, line) |
|----|-------|----------------------|
| F1 | — | A subscription that carries FILL_PARAMETERS opens a unidirectional FETCH_HEADER stream, the fill fetch stream. (§3.4 l.1540) |
| F2 | normative definition | The fill range is the LOCATION_FILTER inside FILL_PARAMETERS. **If that filter is omitted, it is the subscription's Location filter**, evaluated with the Fetch rules of §9.20.9, so it never goes past Largest Object. With no subscription filter, or a zero-length or 0x00 filter, it is the whole track up to Largest. (§3.4 l.1546-1552) |
| F3 | — | If the range is empty, or starts after Largest Object, no fill stream is opened. (§3.4 l.1559-1560) |
| F4 | — | The FETCH_HEADER Request ID is the SUBSCRIBE's or the REQUEST_UPDATE's. Several fill streams can be open at once, and a new one does not cancel earlier ones. (§3.4 l.1579-1585) |
| F5 | — | FILL_PARAMETERS sent while the subscription is paused opens nothing. Resuming without FILL_PARAMETERS opens nothing. A REQUEST_UPDATE without FILL_PARAMETERS opens nothing. (§3.4.1 l.1596-1605) |
| F6 | MUST | When the subscription is cancelled, every open fill stream is reset. (§3.4.1 l.1607) |
| F7 | MUST | A fill completes with FIN. A failure is signalled by a reset: the publisher "MUST open a fill fetch stream and reset it immediately after the FETCH_HEADER if necessary". (§3.4.1 l.1610-1615) |
| F8 | — | STOP_SENDING or a reset on one fill stream does not affect the subscription. (§3.4.1 l.1615-1619) |
| F9 | — | PUBLISH_DONE's Stream Count includes fill fetch streams. (§9.9 l.4664-4670) |
| F10 | MUST | FILL_PARAMETERS carries Parameters "as if they were Parameters for a separate message". An unknown or out-of-version Message Parameter closes the session with PROTOCOL_VIOLATION. (§9.20.15 l.5476; §9.20 l.5084-5087) |
| F11 | MUST | FILL_TIMEOUT 0 means no waiting upstream. The hub never fetches upstream, so this is met trivially. (§9.20.5) |

Rulings in the ledger: Q-02 (0x00 and zero-length both mean "no filter"), Q-07, and Q-08 (reset codes: CANCELLED, DELIVERY_TIMEOUT, INTERNAL_ERROR). Q-02 does **not** cover the *omitted* case in F2.

## Implementation (moqtrun.c @206c185)

| function | line | behaviour |
|----------|------|-----------|
| `moqtrun_accept_subscribe` | :1399 | Queues SUBSCRIBE_OK (:1407), *then* calls `moqtrun_fill_on_subscribe` (:1408). |
| `moqtrun_update_sub` | :2815 | Queues REQUEST_OK (:2830), *then* calls `moqtrun_fill_on_update` (:2831). |
| `moqtrun_fill_from_param` | :2382 | A malformed value returns silently (:2391). |
| `moqtrun_fill_rl` | :2342 | `has_filter == 0` means the whole track. |
| `moqfetch_fill_filter_of` | moqfetch.c:285 | Gives `has_filter == 0` for both an absent filter and 0x00. |
| `moqtrun_fill_open` | :2352 | Resolves the range; an empty one opens nothing. Takes a `fetches[]` slot, otherwise a `fetch_waits[]` slot. |
| `moqtrun_fill_wait_put` | :2299 | When both tables are full, returns at :2307 and the fill is dropped. |
| `moqtrun_fetch_open` | — | A refused open is retried. A failed fill is opened and then reset. |
| `moqtrun_fetches_cancel` | — | Resets open fills and frees held ones (on request reset). |
| `moqtrun_sub_done` | :6790 area | PUBLISH_DONE is deferred while a counted fill is still held. |

## Model variables

| variable | meaning |
|----------|---------|
| `sub` | subscription state: idle, live, cancelled or ended |
| `sflt` | subscription Location filter |
| `fwd` | FORWARD |
| `nUpd` | number of REQUEST_UPDATEs |
| `reqs` | one record per FILL_PARAMETERS, with fields `owner`, `n` (0 = SUBSCRIBE), `ff`, `spec`, `impl`, `paused`, `st`. `spec` and `impl` are ranges; `st` is one of none, wait, held, open, fin, reset, dropped, freed. |
| `failed` | upstream gone |
| `closed` | session closed |
| `doneSent`, `doneCnt` | PUBLISH_DONE emitted, and its Stream Count |

Constants: LG (Largest group) is 2. Slots and Waits are the `fetches[]` and `fetch_waits[]` capacities, scaled down from 8+8.
