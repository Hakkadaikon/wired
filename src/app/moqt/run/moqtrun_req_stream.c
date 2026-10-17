#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_req_slot_free(const wired_moqt_hub* hub, usz i);
static void moqtrun_req_stream_reset(wired_moqtrun_req* q);
static void moqtrun_req_body_reset(wired_moqtrun_req* q);

wired_moqtrun_req* moqtrun_req_find(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 stream_id) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_req_is(&hub->reqs[i], s, stream_id)) {
      return &hub->reqs[i];
    }
  }
  return 0;
}

/* A free slot no subscription still owes a NAMESPACE_DONE for
 * (wired_moqtrun_req.ns_seen). */
static int moqtrun_req_slot_free(const wired_moqt_hub* hub, usz i) {
  return !hub->reqs[i].in_use && !moqtrun_disc_held(hub, i);
}

wired_moqtrun_req* moqtrun_req_free_slot(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_req_slot_free(hub, i)) {
      return &hub->reqs[i];
    }
  }
  return 0;
}

/* A peer-opened bidi stream: the hub is always the server, and RFC 9000
 * 2.1 numbers client-initiated bidi streams 0 mod 4. Needs the io's
 * reply op to answer on it. */
int moqtrun_req_stream_ok(const wired_moqt_hub* hub, u64 stream_id) {
  return (stream_id & 3) == 0 && hub->io.stream_reply_open != 0;
}

/* q's stream-level state: framing, send slots, FIN/GOAWAY flags. */
static void moqtrun_req_stream_reset(wired_moqtrun_req* q) {
  q->opened       = 0;
  q->in.n         = 0;
  q->in.at        = 0;
  q->in.skip      = 0;
  q->send_lens[0] = 0;
  q->send_lens[1] = 0;
  q->armed_idx    = 0;
  q->goaway       = 0;
  q->live         = 0;
  q->rdv_held     = 0;
  q->fin_in       = 0;
  q->fin_out      = 0;
}

/* q's request-level state: discovery, updates and the PUBLISH it drives. */
static void moqtrun_req_body_reset(wired_moqtrun_req* q) {
  q->done_pending = 0;
  q->done_status  = 0;
  q->done_count   = 0;
  q->ns_len       = 0;
  bytes_memset(q->ns_seen, 0, sizeof q->ns_seen);
  q->pending_updates = 0;
  bytes_memset(q->attempted_tag, 0, sizeof q->attempted_tag);
  q->pub_origin_rid = 0;
  q->pub_track_tag  = 0;
  q->pub_alias      = 0;
  q->has_forward    = 0;
  q->forward        = 0;
  q->group_order    = 0;
  q->rngf_n         = 0;
  q->pub_answered   = 0;
}

wired_moqtrun_req* moqtrun_req_open(
    wired_moqtrun_req* q, wired_wt_session* s, u64 stream_id) {
  q->in_use     = 1;
  q->wt         = s;
  q->stream_id  = stream_id;
  q->kind       = 0;
  q->request_id = MOQTRUN_RID_NONE;
  moqtrun_req_stream_reset(q);
  moqtrun_req_body_reset(q);
  return q;
}

int moqtrun_req_owned(const wired_moqtrun_req* q, wired_wt_session* s) {
  return q->in_use && q->wt == s;
}

usz moqtrun_req_count(const wired_moqt_hub* hub, wired_wt_session* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    n += (usz)moqtrun_req_owned(&hub->reqs[i], s);
  }
  return n;
}

/* A fresh slot for a new request stream of s, or -- s at its share of the
 * pool, or the pool full -- the stream is reset with EXCESSIVE_LOAD and 0
 * returned. */
wired_moqtrun_req* moqtrun_req_admit(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id) {
  wired_moqtrun_req* q =
      moqtrun_req_count(hub, s) < WIRED_MOQTRUN_MAX_REQS_PER_SESSION
          ? moqtrun_req_free_slot(hub)
          : 0;
  if (q) {
    return moqtrun_req_open(q, s, stream_id);
  }
  hub->io.stream_reset(s, stream_id, MOQTRUN_RESET_EXCESSIVE_LOAD);
  return 0;
}
