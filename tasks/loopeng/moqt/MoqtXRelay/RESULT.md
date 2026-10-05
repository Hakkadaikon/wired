# MoqtXRelay: TLC results (ledger 7-1 (c))

TLC2 2026.10.04 was run with `-workers 1`. Logs are in `logs/<cfg>.out`. Code was
read at HEAD `206c185`.

## Invariants and properties

**Safety invariants:**

| invariant | what it checks |
|-----------|----------------|
| `EncodedForDest` | Every message to d is encoded in d's draft. |
| `FeaturesSupported` | Nothing sent to d uses a feature d's draft lacks. |
| `UnsupportedRefused` | A request carrying a feature its sender's draft lacks ends in a PROTOCOL_VIOLATION close. |
| `NoSilentDrop` | — |
| `SubCorrespondence` | Hub subscriptions correspond to accepted SUBSCRIBEs, only while the track is live, and there is at most one per track on draft-18. |
| `FetchCorrespondence` | An accepted FETCH has a FETCH_OK in the requester's draft, and a Joining FETCH occurs only on 18/19. |
| `FillOnlyOn22` | — |

**Liveness under WF of request processing:** `RequestResolved`: every request is eventually answered or its session closed.

## Runs

Every run uses Subs={a,b}, MaxReq=2 and request features {base, fill, joining, rangefilter}.

| cfg | versions (pub / a / b) | silent-drop path | states generated / distinct / depth | result |
|-----|------------------------|------------------|-------------------------------------|--------|
| `MC_p19_a18_b22` | 19 / 18 / 22 | spec | 793,393 / 273,252 / 12 | **No error** |
| `MC_p22_a18_b19` | 22 / 18 / 19 | spec | 890,782 / 287,616 / 12 | **No error** |
| `MC_p18_a22_b22` | 18 / 22 / 22 | spec | 1,108,297 / 357,336 / 12 | **No error** |
| `MC_shipped_p22_a19` | 22 / 19 / 22 | shipped (`moqtrun.c:1739`) | 113 / 105 / 3 | **Violated:** `UnsupportedRefused` (F-C1) |
| `MC_mut_enc` | mutation: encode with the publisher's draft | spec | 19 / 16 / 3 | Violated `EncodedForDest`; the mutation is killed. |
| `MC_mut_done` | mutation: PUBLISH_DONE status passed through without mapping | spec | 206 / 125 / 5 | Violated `FeaturesSupported`; the mutation is killed. |

The three spec-path runs say that the hub's routing and encoding structure is
correct for every pair of drafts. This covers:

- per-destination encoding;
- the version gates on DUPLICATE_SUBSCRIPTION, SUBSCRIPTION_ENDED and 0x20C;
- fill only on 22;
- a draft-22 Joining FETCH closing the session;
- PUBLISH_STATE_NOTIFY not being forwarded.

These hold *provided* a request whose decode fails closes the session. The shipped
SUBSCRIBE path does not meet that condition.

## Findings

### F-C1 (real): a cross-version SUBSCRIBE carrying a parameter its sender's draft lacks is silently ignored

Trace (`logs/shipped_p22_a19.out`, depth 3):

1. Subscriber a negotiated draft-19 and sends a SUBSCRIBE carrying FILL_PARAMETERS (0x23, a draft-22-only parameter). The publisher is on draft-22.
2. `moqctl_subscribe_take(MOQVER_D19, …)` rejects the parameter: the draft-19 column of `MOQCTL_PARAM_RULES` is 0, so `moqctl_param_admit` returns VIOLATION.
3. `moqtrun_handle_subscribe` returns at moqtrun.c:1739. No PROTOCOL_VIOLATION close, no REQUEST_ERROR and no SUBSCRIBE_OK is sent. The request stream hangs.

19 §10.2 requires a PROTOCOL_VIOLATION close (l.3332-3335). The same pattern applies to:

- a draft-18 SUBSCRIBE with a Range Filter (0x25-0x29);
- PUBLISH (:910);
- TRACK_STATUS (:2602);
- PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE (:3277);
- SUBSCRIBE_TRACKS (:3496).

FETCH (:2546) and REQUEST_UPDATE already close correctly, and the fix should give the paths above the same shape.

This is the cross-version form of the ledger's 5-2 rule "a feature that exists in only one draft is refused in that draft". Because the hub serves everything locally, the refusal must happen at the *sender's* decode, and today it is silent.

### Holds as modeled

- `EncodedForDest` and `FeaturesSupported` hold across all draft pairs.
- A d22 subscriber's fill on a track published over 18 or 19 is served from the cache with 0x20C allowed, which is correct for the destination.
- A d18 or d19 subscriber never receives a fill stream or 0x20C.
- A d18 subscriber gets DUPLICATE_SUBSCRIPTION and no other draft does.
- PUBLISH_DONE SUBSCRIPTION_ENDED is mapped to TRACK_ENDED for 22.
- A d22 Joining FETCH closes the session; d18 and d19 Joining FETCHes correspond to the requester's own subscription.
