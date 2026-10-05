# Rendezvous (RENDEZVOUS_TIMEOUT): requirements extraction

Sources, read from the local copies, not from search snippets:
`tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt` (dated May 2026, July 2026
and October 2026). Interop runner: `/home/user/moq-interop-runner` (docs +
`builds/`). Reference client: `cloudflare/moq-rs` branch `draft-18-dev` @
`52b8a905`, which is the source of the `moq-rs-draft-18` client image. I cloned it
into the session scratchpad. It is not in the repo.

## 0. Section map

| Topic | d18 | d19 | d22 |
|---|---|---|---|
| RENDEZVOUS_TIMEOUT param (0x04) | 10.2.6 (l.3309) | 10.2.6 (l.3589) | 9.20.6 (l.5199) |
| Exactly one SUBSCRIBE_OK / error | 5.1 (l.1936) | 5.1 (l.2048) | 3.1 (l.1096) |
| Relay: Established upstream before SUBSCRIBE_OK | 9.4 | 9.4 | 7.4 |
| Relay: PUBLISH / PUBLISH_NAMESPACE vs held SUBSCRIBE | 9.5 (l.2819) | 9.5 (l.3115) | 7.6 (l.3158) |
| FIN = half-close, not cancel | (none) | 3.3.2 | 6.4.2.2 |
| Request cancellation | 3.3.2 | 3.3.3 | 6.4.2.3 |
| GOAWAY | 10.4 | 10.4 | 9.2 |
| Session termination | 3.5 | 3.5 | 6.6 |
| Request error code meanings | 10.6 | 10.6 | 12.3 |
| Request error code registry (TIMEOUT 0x2, EXCESSIVE_LOAD 0x9, DOES_NOT_EXIST 0x10, GOING_AWAY 0x6) | 15.10.2 | 15.11.2 | 16.11.2 |
| "SUBSCRIBE_ERROR" = REQUEST_ERROR shorthand | n/a | n/a | 1.5 |

The RENDEZVOUS_TIMEOUT text is identical in d18 and d19. d22 differs in one
way only: it writes `SUBSCRIBE_ERROR` where d18 and d19 write `REQUEST_ERROR`.
d22 §1.5 defines SUBSCRIBE_ERROR as "a REQUEST_ERROR sent in response to"
SUBSCRIBE, so the wire message (0x05) and the codes are the same. **No
behavior differs between versions.**

## 1. RENDEZVOUS_TIMEOUT rules (d18/19 10.2.6, d22 9.20.6)

| ID | Level | Text (verbatim core) | Notes |
|---|---|---|---|
| R1 | MAY | "The RENDEZVOUS_TIMEOUT parameter (Parameter Type 0x04) MAY appear in a SUBSCRIBE message." | wired decodes it as a varint. moqctl.c:869 ctx bits are d22 0x1, d19 0x1001, d18 0x1. d19 also allows it on SUBSCRIBE_TRACKS through d19 10.19.1 ("Any Parameter that can be specified on a Subscription ... is valid in SUBSCRIBE_TRACKS"). SUBSCRIBE_TRACKS already waits with no limit, so the value has no effect there. |
| R2 | def | "the duration in milliseconds the subscriber is willing to wait for a publisher to become available. This applies when a relay receives a SUBSCRIBE for a Track that has no current publisher." | Unit is ms. The rule applies only when the Track has no current publisher. |
| R3 | SHOULD | "If the RENDEZVOUS_TIMEOUT is present, the relay SHOULD hold the subscription and wait for a publisher to appear, up to the specified duration." | Hold. |
| R4 | (normative-descriptive) | "The relay does not send SUBSCRIBE_OK until a publisher becomes available." | No early SUBSCRIBE_OK. Same as 9.4/7.4 MUST: "The relay MUST have an Established upstream subscription before sending SUBSCRIBE_OK". |
| R5 | (desc) | "If a publisher becomes available within this time, the relay proceeds with the subscription normally." | "Normally" means the ordinary relay path in 9.5/7.6: a PUBLISH gives an Established upstream subscription now, and a PUBLISH_NAMESPACE means sending an upstream SUBSCRIBE and waiting for its SUBSCRIBE_OK. |
| R6 | SHOULD | "If the timeout expires without a publisher, the relay SHOULD respond with REQUEST_ERROR [d22: SUBSCRIBE_ERROR] with error code TIMEOUT." | Code TIMEOUT = 0x2 in all three registries. |
| R7 | MAY | "The relay MAY use a shorter timeout than requested by the subscriber. For example, a relay might limit the maximum rendezvous timeout to protect its resources." | Clamp is allowed. |
| R8 | MUST | "A value of 0 indicates the subscriber does not want to wait and expects an immediate response. The relay MUST immediately return REQUEST_ERROR [d22: SUBSCRIBE_ERROR] with error code DOES_NOT_EXIST if no publisher is available" | 0 means DOES_NOT_EXIST at once. This is wired's current behavior for every SUBSCRIBE. |
| R9 | def | "If RENDEZVOUS_TIMEOUT is absent, the default is 0." | Absent is the same as R8. A plain SUBSCRIBE with no publisher gets DOES_NOT_EXIST at once. |

Error-code meanings (d18/19 10.6, d22 12.3):
- `TIMEOUT`: "The subscription could not be completed before an implementation
  specific timeout. For example, a relay could not establish an upstream
  subscription within the timeout." This covers both the "no publisher" expiry
  and an upstream SUBSCRIBE that is still unanswered at the deadline.
- `DOES_NOT_EXIST`: "The track or namespace is not available at the publisher."
- `EXCESSIVE_LOAD`: "The responder is overloaded and cannot process the request
  at this time. The sender SHOULD use the Retry Interval to indicate when the
  request can be retried." This is the honest code when the hold table is full.
- `GOING_AWAY`: "The endpoint has received a GOAWAY and MAY reject new requests."
- Retry Interval (d18 10.6): non-zero only "If a request is retryable with the
  same parameters at a later time". "1 indicates the request can be retried
  immediately".

### Which error code, when

| Situation | Code | Rule |
|---|---|---|
| no param / 0, no publisher | DOES_NOT_EXIST | R8/R9 MUST |
| param > 0, deadline passed with no publisher | TIMEOUT | R6 SHOULD |
| param > 0, upstream SUBSCRIBE (after PUBLISH_NAMESPACE) still unanswered at deadline | TIMEOUT | R6 + 10.6 TIMEOUT example |
| param > 0, relay clamps to a shorter window | TIMEOUT at the clamped deadline | R7 MAY |
| param > 0, relay cannot hold (table full) | EXCESSIVE_LOAD with Retry Interval (design choice, see design.md §6) | 10.6 |
| hub-side request from a session that sent GOAWAY to us / drain | GOING_AWAY (only for NEW requests at or past the GOAWAY Request ID, d18 10.4 MUST) | 10.4 |

## 2. Exactly-once answer

- d18/19 5.1, d22 3.1 MUST: "A publisher MUST send exactly one SUBSCRIBE_OK or
  REQUEST_ERROR [d22 SUBSCRIBE_ERROR] in response to a SUBSCRIBE." d22 adds:
  "The peer SHOULD close the session with a protocol error if it receives more
  than one." **A late upstream answer after a TIMEOUT must not produce a second
  reply.** That case is TLA+ `AtMostOneAnswer` plus the `up = "stale"` handling.
- d19 3.3.2 / d22 6.4.2.2 MUST: "an endpoint sending a response to a request
  MUST send the corresponding response message ... before sending a FIN". The
  hub must not FIN a held request stream. wired's `moqtrun_req_settle` would do
  exactly that (TLA+ `MC_bug.cfg`).

## 3. Publisher arrival

- PUBLISH (d18/19 9.5, d22 7.6, MUST): "When a relay receives an incoming
  PUBLISH message, it MUST send a PUBLISH request to each subscriber that has
  sent SUBSCRIBE_TRACKS for the Track's namespace or a prefix thereof. However,
  if the relay is holding a downstream SUBSCRIBE awaiting a publisher for this
  Track (see Section 10.2.6 / 9.20.6), it MUST proceed with the SUBSCRIBE and
  MUST NOT also forward the PUBLISH to that subscriber."
  - What this requires: resolve the hold with SUBSCRIBE_OK, and skip that session
    in the SUBSCRIBE_TRACKS fan-out for this track.
- PUBLISH acceptance (d18/19 9.5 MUST): "When it receives an authorized PUBLISH
  message for a Track that has Established downstream subscriptions, it MUST
  respond with PUBLISH_OK. If at least one downstream subscriber for the Track
  has Forward State=1, the Relay MUST use Forward State=1 in the reply." d22 7.6
  says the same with pause/resume wording. wired's PUBLISH_OK today carries only
  LARGEST_OBJECT. That is fine for Forward=1, but see §6 for `moq-test-forward-zero`.
- PUBLISH_NAMESPACE (d18/19 9.5, d22 7.6, MUST): "When a relay receives an
  authorized PUBLISH_NAMESPACE for a namespace that matches one or more existing
  subscriptions to other upstream sessions, it MUST send a SUBSCRIBE to the
  publisher that sent the PUBLISH_NAMESPACE for each matching subscription."
  For a SUBSCRIBE that arrives while a namespace publisher already exists:
  "If there are no Established upstream subscriptions for the requested Track,
  the Relay MUST send a SUBSCRIBE request to each publisher that has published
  the subscription's namespace or prefix thereof." SUBSCRIBE_OK goes downstream
  only after the upstream SUBSCRIBE_OK (9.4/7.4 MUST).
  - **wired gap (independent of rendezvous):** the hub never originates an
    upstream SUBSCRIBE. `moqtrun_route_peer_subscribe` matches only tracks
    claimed by PUBLISH (`moqtrun_find_published_track`). A PUBLISH_NAMESPACE-only
    publisher is never subscribed to, so even the no-rendezvous
    `announce-subscribe` flow is answered DOES_NOT_EXIST.
- Multiple publishers (d18/19 9.3): relays "maintain subscriptions to all
  available publishers". The TLA+ model abstracts this to one upstream at a time.

## 4. Cancellation and closure

| Event | Rule | Effect on a held SUBSCRIBE |
|---|---|---|
| Subscriber RESET_STREAM / STOP_SENDING on the request stream | d18 3.3.2 SHOULD, d19 3.3.3 / d22 6.4.2.3: "Implementations cancel a request by abruptly terminating any directions of the stream that are still open" | Cancelled. Drop the hold and send nothing. Any upstream SUBSCRIBE made for it is cancelled too. |
| Subscriber FIN after SUBSCRIBE | d19 3.3.2 / d22 6.4.2.2: "A FIN only indicates that an endpoint will send no further messages in that direction; it is not a request cancellation." "A requester ... MAY FIN immediately after sending a message if it will not send a REQUEST_UPDATE." d18 has no such text; wired's d18 FIN-cancel cap (`MOQVER_CAP_FIN_CANCEL_NS`, d18 6.1) covers only SUBSCRIBE_NAMESPACE / SUBSCRIBE_TRACKS. | **Not cancelled.** The hold continues and the answer is still owed. |
| UNSUBSCRIBE | No UNSUBSCRIBE message in d18/19/22. The word appears only in GOAWAY prose (d18/19 10.4 "SHOULD individually UNSUBSCRIBE", d22 9.2 "unsubscribe from"), which means cancelling the request stream. | Same as RESET. |
| REQUEST_UPDATE on a held SUBSCRIBE | d19 10.9: "The receiver of a REQUEST_UPDATE MUST respond with exactly one REQUEST_OK or REQUEST_ERROR" | The first response on the stream reads as the SUBSCRIBE's answer, so the hold must be answered first (design.md §5.6). |
| Subscriber session closes | d18/19 3.5, d22 6.6 | Every hold of that session is dropped silently. The streams are gone. |
| Publisher session closes / PUBLISH cancelled / namespace withdrawn | 9.5/7.6 | A hold that was not yet resolved is unaffected. It keeps waiting. An upstream SUBSCRIBE in flight to that publisher fails, and the request goes back to held until its deadline. After resolution it is an ordinary subscription (PUBLISH_DONE path, out of scope here). |
| Hub sends GOAWAY to the subscriber | d18/19 10.4, d22 9.2: "The GOAWAY message does not impact subscription state."; d18: requests with Request ID >= the GOAWAY's "MUST be rejected with REQUEST_ERROR using error code GOING_AWAY" | A hold that already exists has a Request ID below the GOAWAY's (the hub sends `peer_rid_next`), so it continues. A NEW SUBSCRIBE after GOAWAY: the hub MAY (d19/22) or MUST (d18, ID >= the GOAWAY's) reject it with GOING_AWAY. That is existing GOAWAY behavior, not rendezvous. At the GOAWAY_TIMEOUT close, holds are dropped with the session. |
| Subscriber sends GOAWAY to the hub | 10.4 / 9.2: the receiver "SHOULD NOT initiate new requests" | No effect on holds. The hub does not initiate anything for a hold except, under G1, an upstream SUBSCRIBE to a *publisher* session. |

## 5. Interop testcases (what each checks)

`docs/tests/TEST-CASES.md` lines are in the runner repo. The `moq-rs` lines are
from `moq-test-client/src/` @ 52b8a905.

| Case | Defined at | Flow | Pass condition | Needs rendezvous? |
|---|---|---|---|---|
| `subscribe-error` | TEST-CASES.md:120-148; moq-rs scenarios.rs:174 | SUBSCRIBE `nonexistent/namespace` with no param | any REQUEST_ERROR | No. Already passes. Must keep DOES_NOT_EXIST for no param (R9). |
| `rendezvous-timeout` | TEST-CASES.md:152-176; moq-rs scenarios.rs:236-298 (`RENDEZVOUS_TIMEOUT_MS = 500` l.45, response budget 2 s l.48) | SUBSCRIBE `nonexistent/rendezvous`/`test-track` with RENDEZVOUS_TIMEOUT=500 | **REQUEST_ERROR with code TIMEOUT**, within 2 s. "A relay may use a shorter timeout than requested, so the test does not impose a minimum wait" (l.172). moq-rs maps only `ServeError::Timeout` to pass (l.287); DOES_NOT_EXIST fails ("expected REQUEST_ERROR TIMEOUT"). stitcher-moq skips it (builds/stitcher-moq/src/main.rs:279-284). | **Yes, this is exactly R6.** |
| `announce-subscribe` | TEST-CASES.md:180-211; moq-rs scenarios.rs:303-366; stitcher main.rs:481-560 | pub PUBLISH_NAMESPACE `moq-test/interop`, then a plain SUBSCRIBE `test-track` (no param) | Spec: subscriber receives SUBSCRIBE_OK. moq-rs accepts any answer (it only logs). stitcher fails on REQUEST_ERROR (l.545). aiomoqt fails with "upstream subscribe failed" (ledger l.241). | **No.** It needs the upstream SUBSCRIBE to the namespace publisher (gap G1, §3). Rendezvous alone does not fix it. |
| `subscribe-before-announce` | TEST-CASES.md:215-247; moq-rs scenarios.rs:600-680; stitcher main.rs:572-720 | plain SUBSCRIBE first (no param in either client), PUBLISH_NAMESPACE 500 ms later | Spec: SUBSCRIBE_OK eventually **or** REQUEST_ERROR. moq-rs passes either way. stitcher waits for the NAMESPACE routing (SUBSCRIBE_NAMESPACE) and only then SUBSCRIBEs, so it effectively becomes announce-subscribe and fails on REQUEST_ERROR. | **No** (no RENDEZVOUS_TIMEOUT is sent). It needs G1. |
| `publish-track-subscribe` | moq-rs main.rs:157, scenarios.rs:481-598 (not in TEST-CASES.md; moq-rs extension) | pub PUBLISH `moq-test/publish`/track and waits for PUBLISH_OK, *then* a plain SUBSCRIBE; publisher writes one Object after 100 ms and ends the track | subscriber receives the object **and** `subscribe()` returns, which needs PUBLISH_DONE relayed (`subscribe.closed()`, subscriber.rs:551-553) | **No rendezvous** (publish-first). It needs the relay to forward the publisher's PUBLISH_DONE (gap G2: wired skips inbound PUBLISH_DONE, `moqtrun_dispatch_skip` at moqtrun.c:3963). The ledger's "Not found" for this case is unconfirmed: there is no run log in the repo. |
| `moq-test-*` (9 cases: subgroup-per-group[-eog], subgroup-per-object, two-subgroups-eog, datagram[-eog], extensions, increments, forward-zero) | moq-rs moqtest.rs:1200-1335 (scenario table), run() 1380-1500 | **Subscribe-first**: SUBSCRIBE with RENDEZVOUS_TIMEOUT=**5000** (l.77, l.1401) on namespace `moq-test-00/<tuple>` (16 fields, l.64-67) and a random track name, then 200 ms later a second session sends a direct **PUBLISH** of the same track. The publisher waits for the subscriber's SUBSCRIBE_OK (oneshot, l.1413/1466) before generating. | subscriber SUBSCRIBE_OK (else "subscriber setup failed before generation started", the observed failure), then every object, EOG marker and extension, then **PUBLISH_DONE status TRACK_ENDED with the exact stream count** (moqtest.rs:1001-1030). `forward-zero`: SUBSCRIBE also carries FORWARD=0, no data may arrive, and PUBLISH_DONE stream_count must be 0 (l.1044-1066). | **Yes**: rendezvous resolved by PUBLISH (R3/R5 + 9.5 MUST proceed). **Also needs:** G2 (relay PUBLISH_DONE with this subscriber's own stream count), datagram forwarding, extension headers forwarded unchanged, and FORWARD=0 honored. The synthetic `moq-test` data generator is **client-side** (the publisher session is the moq-rs client itself). The relay needs no knowledge of the `moq-test-00` namespace format. |

Other clients in this runner checkout (`builds/moq-dev-rs`, `moq-dev-js`,
`stitcher-moq`) have no rendezvous code. Only stitcher mentions it, and only
to skip it.
