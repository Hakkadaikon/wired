# Upstream SUBSCRIBE to a PUBLISH_NAMESPACE publisher (ledger 12-3)

Rules: d18/19 9.4 + 9.5, d22 7.4 + 7.6 -- "MUST send a SUBSCRIBE request to
each publisher that has published the subscription's namespace or prefix
thereof", "MUST have an Established upstream subscription before sending
SUBSCRIBE_OK", "MAY aggregate". d18 removed MAX_REQUEST_ID (#1471): the only
request limit is the QUIC bidi stream limit, i.e. `io.open_bidi_stream`
failing. Model: `UpstreamSub.tla` (RESULT.md).

## Shape: reuse, three new pieces

1. **Waiters are rendezvous holds.** `moqtrun_rdv_miss` now holds a
   SUBSCRIBE also when its rt is 0 but a namespace publisher matches
   (`moqtrun_up_announced`). Such a hold has `up_only = 1` and no deadline
   (TLA+ `NoDl`). Resolution is unchanged: `moqtrun_rdv_resolve(t, k)` once a
   track claims k.
2. **Upstream entries** `hub->ups[WIRED_MOQTRUN_MAX_UP]`
   (`wired_moqtrun_up`): publisher wt, hub-opened request stream id, the
   hub's Request ID (`request_id_next += 2` on the publisher's session, the
   server's odd ids, d18 10.1), the Full Track Name key, reply reassembly,
   and `track_tag` (0 while pending). One entry per key = aggregation.
3. **SUBSCRIBE_OK claims a track slot on the publisher peer** with
   `own_alias` = the SUBSCRIBE_OK's Track Alias, exactly as a PUBLISH would
   (`moqtrun_track_open`, split out of `moqtrun_publish_checked`), then
   `moqtrun_rdv_resolve`. From there the existing machinery carries
   everything: inbound SUBGROUP streams and datagrams route by alias
   (`moqtrun_track_by_alias`), each downstream gets its own alias
   (`moqtrun_session_alias` / `moqtrun_alias_splice`), PUBLISH_DONE relays
   through `moqtrun_pubdone_arm` (split out of `moqtrun_dispatch_pub_done`),
   a publisher session close ends the track (TRACK_ENDED).

## The single decision point: `moqtrun_up_sync` (in `moqtrun_reqs_tick`)

Runs at the end of every dispatch/tick (the model's atomic `Sweep`):

- per entry: publisher session gone or closing -> freed with no io;
  established but its track gone (PUBLISH_DONE finished, superseded) ->
  our side FINned, freed; nobody wants it (no rdv waiter for its key and no
  active subscription on its track) -> RESET_STREAM + STOP_SENDING
  CANCELLED (19 3.3.3), the track retires, freed (`NoLeak`).
- per rdv waiter with no entry for its key: a matching namespace publisher
  (not the waiter's own session) -> SUBSCRIBE opened upstream; none, or the
  open fails -> an `up_only` waiter is answered REQUEST_ERROR now
  (DOES_NOT_EXIST, or EXCESSIVE_LOAD when the stream would not open); a
  rendezvous waiter keeps waiting for its deadline.

A PUBLISH_NAMESPACE arriving later therefore resolves a held SUBSCRIBE with
no extra hook: its dispatch ends in `moqtrun_reqs_tick`.

## Replies on the hub-opened stream (`moqtrun_up_rx`, hooked in
`moqtrun_dispatch_other` ahead of the client-bidi classification)

Table-dispatched by Type: SUBSCRIBE_OK (claim + resolve), REQUEST_ERROR
(every waiter for the key answered with the code, normalized by
`moqctl_known_request_error` and re-spelled for each subscriber's draft by
`moqtrun_send_request_error`; entry freed, our side FINned), PUBLISH_DONE
(armed on the track; `moqtrun_pubdone_try` relays it with each
subscription's own stream count). Anything else is ignored. A reply on a
stream whose entry was already cancelled finds no entry (TLA+ stale
generation).

## Upstream SUBSCRIBE content

No parameters: FORWARD defaults to 1 (9.5 "If the SUBSCRIBE has Forward=1,
the Relay MUST use Forward=1 upstream"), no filter = unfiltered (10.2.x). The
downstream filters are applied per subscription by the existing relay gates
(9.4 aggregation note).

## Deliberate limits (ponytail)

- One upstream per Full Track Name, to the first matching announcer: 9.5
  says "each publisher"; the hub keys one track per name
  (`moqtrun_supersede_name`), so a second upstream for the same name would
  retire the first. Interop has one publisher.
- Established subscriptions do not trigger SUBSCRIBEs to a namespace
  announced later (9.5's second clause); only waiting SUBSCRIBEs do.
- A SUBGROUP stream that overtakes its SUBSCRIBE_OK finds no alias and is
  dropped (as an unknown alias always is).
- An `up_only` waiter has no deadline (the model's NoDl): it ends with the
  upstream's answer, the publisher's departure, or its own cancel.
