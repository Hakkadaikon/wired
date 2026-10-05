# MoqtXRelay: requirements and variables (ledger 7-1 (c), items 5-1/5-2)

Spec: `tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt`. Code was read at HEAD `206c185`.

## Relay shape in wired (from the code)

The hub never forwards SUBSCRIBE or FETCH upstream:

- SUBSCRIBE is matched against tracks that peers have PUBLISHed (`moqtrun_route_subscribe`).
- FETCH and fill are served from the hub cache (`moqtrun_fetch_standalone`, `moqtrun_fill_open`).
- The data plane (SUBGROUP streams and datagrams) is relayed byte for byte. Item 5-1 established that these bytes are identical across 18, 19 and 22.
- Every control message goes through `moqtrun_envelope_put`, using the destination peer's `p->ver` and the per-draft encoders:
  - `moqtrun_fetch_ok_encoder`
  - `moqtrun_goaway_encoder`
  - `moqctl_request_error_for`
  - `moqctl_publish_done_for`
  - the version-aware `moqctl_*_take`

So cross-version correspondence means two things. First, each request is decoded in the *sender's* draft and answered in the *sender's* draft. Second, nothing generated from another peer's state, such as PUBLISH_DONE on publisher loss, SUBSCRIBE_TRACKS-generated PUBLISH or relayed Objects, carries a feature the destination's draft lacks.

## Spec requirements

| id | level | text (section) |
|----|-------|----------------|
| X1 | MUST | Every Message Parameter must be defined in the negotiated version; an unknown one closes the session with PROTOCOL_VIOLATION. (18 §10.2 l.3041-3044, 19 §10.2 l.3332-3335, 22 §9.20 l.5084-5087) |
| X2 | MUST | An unknown message type closes the session. (18 l.2973; 19/22 same) |
| X3 | — | A draft-22 FETCH has a single shape, so the Joining structure is a PROTOCOL_VIOLATION (22 §9.11; wired 4-5). |
| X4 | — | Draft-only codes: DUPLICATE_SUBSCRIPTION 0x19 exists only in 18 (18 §10.6 table l.6866). PUBLISH_DONE SUBSCRIPTION_ENDED 0x3 exists only in 18/19 (19 l.7327; absent from the 22 list l.6921-6952). |
| X5 | — | 0x20C End of Timed-Out Range exists only in 22 (22 §11.4.1); 18/19 treat it as an unknown serialization flag. |
| X6 | — | Relays do not forward Message Parameters (19 §10.2 l.3328-3330). |
| X7 | MUST | A Mandatory Track Property that is not understood is refused UNSUPPORTED_EXTENSION (22 §3.x l.1792-1818). The hub never forwards Track Properties, so this does not apply here. |

## Implementation points modeled

| function | line | behaviour |
|----------|------|-----------|
| `moqtrun_handle_subscribe` | :1735 | A decode failure returns at :1739 with no close and no answer. |
| `moqtrun_handle_publish` | — | Same pattern at :910. |
| `moqtrun_tstat_answer` | — | Same pattern at :2602. |
| `moqtrun_disc_*` | — | Same pattern at :3277. |
| SUBSCRIBE_TRACKS handler | — | Same pattern at :3496. |
| `moqtrun_handle_fetch` | :2546 | A decode failure closes with PROTOCOL_VIOLATION (correct). |
| `moqtrun_fetch_route` | — | A draft-22 Joining FETCH closes (correct). |
| `moqtrun_sub_held_reply` | — | DUPLICATE_SUBSCRIPTION only when the destination has `CAP_DUP_SUBSCRIPTION`. |
| `moqtrun_fetch_accept` and `moqtrun_fill_flag` | — | 0x20C is allowed only for the destination's draft. A fill exists only on 22, because FILL_PARAMETERS decodes only there. |
| `moqctl_publish_done_for` | — | Maps SUBSCRIPTION_ENDED to TRACK_ENDED on 22. |
| `moqtrun_dispatch_pub_notify` | — | Absorbs PUBLISH_STATE_NOTIFY and never forwards it. |

## Model variables

| variable | meaning |
|----------|---------|
| `published`, `ended` | track liveness |
| `subs` | the hub's subscription table |
| `reqs` | requests, with fields `id`, `from`, `k` (SUBSCRIBE or FETCH), `f` (base, fill, joining or rangefilter), `st` (pending, ok, err, closed or ignored) |
| `out[d]` | every message or stream sent to d, as `[t, enc, feats]` |
| `closed[d]` | d's session is closed |
| `nReq[d]` | number of requests d has sent |
