#include "app/moqt/run/moqtrun_impl.h"

static usz moqtrun_hold_replay_one(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz at);
static int  moqtrun_hold_ready(const wired_moqtrun_peer* p);
static int  moqtrun_hold_more(const wired_moqtrun_peer* p, usz at, usz n);
static void moqtrun_dispatch_uni_fresh(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
static int moqtrun_stream_parked(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
static void moqtrun_dispatch_pub_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);

/* Holds one delivery for replay. One that does not fit is lost: a
 * request stream is reset EXCESSIVE_LOAD now -- before establishment,
 * never after (3.3.4) -- while an Object stream is silently dropped
 * (only its own pre-SETUP bytes are lost). */
void moqtrun_hold_push(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (p->hold_len + MOQTRUN_HOLD_HDR + data.n <= sizeof p->hold) {
    moqtrun_hold_put(p, sid, data, fin);
    return;
  }
  if ((sid & 3) == 0)
    hub->io.stream_reset(p->wt, sid, MOQTRUN_RESET_EXCESSIVE_LOAD);
}

static usz moqtrun_hold_replay_one(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz at) {
  usz n = moqtrun_hold_rec_len(p, at) - MOQTRUN_HOLD_HDR;
  moqtrun_dispatch_held(
      hub, p, be_get_be64(p->hold + at),
      wired_span_of(p->hold + at + MOQTRUN_HOLD_HDR, n), p->hold[at + 10]);
  return MOQTRUN_HOLD_HDR + n;
}

static int moqtrun_hold_ready(const wired_moqtrun_peer* p) {
  return p->in_use && p->hold_len != 0 && !moqtrun_hold_gate(p);
}

static int moqtrun_hold_more(const wired_moqtrun_peer* p, usz at, usz n) {
  return at < n && !p->closing;
}

/* Replays every held delivery in arrival order once the gate lifts.
 * hold_len drops to 0 first, so a replayed record can never re-hold;
 * the records replay straight out of the log (nothing appends while
 * the gate is open). A session closing mid-replay drops the rest. */
void moqtrun_hold_replay(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  usz at = 0;
  usz n  = p->hold_len;
  if (!moqtrun_hold_ready(p)) return;
  p->hold_len = 0;
  while (moqtrun_hold_more(p, at, n)) at += moqtrun_hold_replay_one(hub, p, at);
}

/* The control/hold/data decision for a FRESH uni delivery. */
static void moqtrun_dispatch_uni_fresh(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_fresh_uni_ctl(hub, p, stream_id, data, fin)) return;
  if (moqtrun_hold_gate(p)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_fresh_stream(hub, p, stream_id, data, fin);
}

/* A later delivery of a stream whose first one is held (pre-SETUP,
 * moqtrun_hold_push) or kept before its SUBSCRIBE_OK (moqtrun_early_more)
 * follows it there. 1 when consumed. */
static int moqtrun_stream_parked(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_hold_has(p, stream_id)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return 1;
  }
  if (!moqtrun_early_more(p, stream_id, data, fin)) return 0;
  moqtrun_early_refetch(hub, p);
  return 1;
}

/* draft 3.4/11.4.2: relay a data stream's bytes verbatim to the
 * subscribers of the track its Track Alias names. A stream_id already in
 * the relay map (an earlier call on this same publisher stream) forwards
 * straight to its recorded subscriber streams -- no re-classification, no
 * header re-decode (later calls carry bare Objects, or nothing at all for
 * a bare FIN). Anything else is treated as fresh. */
static void moqtrun_dispatch_pub_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  wired_moqtrun_track* track = 0;
  wired_moqtrun_relay* relay =
      moqtrun_peer_relay_by_stream(p, stream_id, &track);
  if (relay) {
    moqtrun_relay_continue(hub, track, relay, data, fin);
    return;
  }
  if (moqtrun_stream_parked(hub, p, stream_id, data, fin)) return;
  moqtrun_dispatch_uni_fresh(hub, p, stream_id, data, fin);
}

/* A later delivery of an upstream fetch data stream the hub asked for
 * goes to its fetch (moqtrun_upf_data); anything else as above. */
void moqtrun_dispatch_data_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_upf_data(hub, p, stream_id, data, fin)) return;
  moqtrun_dispatch_pub_stream(hub, p, stream_id, data, fin);
}

int moqtrun_req_is(
    const wired_moqtrun_req* q, const wired_wt_session* s, u64 stream_id) {
  return q->in_use && q->wt == s && q->stream_id == stream_id;
}
