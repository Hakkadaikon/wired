#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_impl_copy(wired_moqtrun_peer* p, const moqctl_setup* m);
static void moqtrun_setup_accept(wired_moqtrun_peer* p, const moqctl_setup* m);
static void moqtrun_dispatch_setup(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
static void moqtrun_dispatch_pub_notify(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
static void moqtrun_dispatch_skip(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);

static void moqtrun_impl_copy(wired_moqtrun_peer* p, const moqctl_setup* m) {
  usz n = (usz)u64_min(m->implementation.n, WIRED_MOQTRUN_IMPL_MAX);
  if (!m->has_implementation) {
    return;
  }
  bytes_memcpy(p->peer_impl, m->implementation.p, n);
  p->peer_impl_len = n;
  p->peer_has_impl = 1;
}

/* Records the accepted client SETUP: the stream it rode becomes the
 * client control stream, its MOQT_IMPLEMENTATION is copied, and the
 * session machine advances (3.3: Established once both sides' SETUP are
 * done). */
static void moqtrun_setup_accept(wired_moqtrun_peer* p, const moqctl_setup* m) {
  p->peer_ctl_set       = 1;
  p->peer_ctl_stream_id = p->rx_sid;
  p->setup_recv         = 1;
  p->peer_max_rngf      = m->max_filter_ranges;
  moqtrun_impl_copy(p, m);
  moqsess_step(&p->sess, MOQSESS_EV_RECV_SETUP);
}

/* Ranges an upstream FETCH to p may carry: its MAX_FILTER_RANGES, on a
 * draft with Range Filters at all (draft-22 9.1.6, draft-19 10.4). */
u64 moqtrun_peer_max_rngf(const wired_moqtrun_peer* p) {
  return (moqver_caps(p->ver) & MOQVER_CAP_RANGE_FILTERS) ? p->peer_max_rngf
                                                          : 0;
}

/* draft-19 3.3/10.4: the client's SETUP, on whichever stream 3.3's
 * leniency lets it arrive. Never reached via a request stream --
 * moqtrun_req_allowed rejects SETUP there first. */
static void moqtrun_dispatch_setup(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqctl_setup m;
  u32          code;
  (void)peer_idx;
  if (moqtrun_setup_second(p)) {
    moqtrun_second_ctl(hub, p);
    return;
  }
  code = moqtrun_setup_take_code(hub, p, body, &m);
  if (code) {
    moqtrun_close_with(hub, p, code);
    return;
  }
  moqtrun_setup_accept(p, &m);
  moqtss_negotiate(hub, p, &m); /* SSTS (moqtssts_run.c) */
}

/* draft-22 9.10: PUBLISH_STATE_NOTIFY rides a subscription's request
 * stream and only from its publisher -- the follow-on gate
 * (moqtrun_req_pub_follow) already admits it there, unanswered. Anywhere
 * else (the control stream lands here with no request; a subscriber's or
 * another request's stream never reaches this handler) the session
 * closes with PROTOCOL_VIOLATION. */
static void moqtrun_dispatch_pub_notify(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  if (p->req) {
    return;
  }
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* A message with no request to refuse: consumed by its Length, no reply. */
static void moqtrun_dispatch_skip(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)p;
  (void)peer_idx;
  (void)body;
}

/* First-type table (draft table in ctl.h's peek_type doc): only PUBLISH,
 * SUBSCRIBE, FETCH, TRACK_STATUS, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE and
 * SUBSCRIBE_TRACKS (and REQUEST_UPDATE of a SUBSCRIBE) are implemented;
 * every other First type this hub can see on a fresh request stream gets
 * NOT_SUPPORTED. GOAWAY is not a First type but may legally appear
 * mid-stream, so it is routed the same table for request-stream dispatch
 * below. */
static const struct {
  u64            type;
  moqtrun_ctl_fn fn;
} moqtrun_ctl_table[] = {
    {MOQCTL_T_SETUP, moqtrun_dispatch_setup},
    {MOQCTL_T_PUBLISH, moqtrun_dispatch_publish},
    {MOQCTL_T_SUBSCRIBE, moqtrun_dispatch_subscribe},
    {MOQFETCH_T_FETCH, moqtrun_dispatch_fetch},
    {MOQNS_T_PUBLISH_NAMESPACE, moqtrun_dispatch_publish_ns},
    {MOQNS_T_SUBSCRIBE_NAMESPACE, moqtrun_dispatch_subscribe_ns},
    {MOQCTL_T_SUBSCRIBE_TRACKS, moqtrun_dispatch_subscribe_tracks},
    {MOQTSTAT_T_TRACK_STATUS, moqtrun_handle_tstat},
    {MOQTSTAT_T_REQUEST_UPDATE, moqtrun_handle_update},
    {MOQCTL_T_GOAWAY, moqtrun_dispatch_goaway},
    {MOQCTL_T_PUBLISH_STATE_NOTIFY, moqtrun_dispatch_pub_notify},
    /* draft SS10 known non-request messages this hub does not implement:
     * nothing carries a Request ID to answer, so they are skipped. */
    {MOQNS_T_NAMESPACE, moqtrun_dispatch_skip},
    {MOQNS_T_NAMESPACE_DONE, moqtrun_dispatch_skip},
    {MOQCTL_T_PUBLISH_SKIPPED, moqtrun_dispatch_skip},
    {MOQFETCH_T_FETCH_OK, moqtrun_dispatch_skip},
    {MOQCTL_T_PUBLISH_DONE, moqtrun_dispatch_pub_done},
    /* answers to the hub's REQUEST_UPDATE on a PUBLISH (moqtrun_pubupd.c) */
    {MOQCTL_T_REQUEST_OK, moqtrun_dispatch_upd_ok},
    {MOQCTL_T_REQUEST_ERROR, moqtrun_dispatch_upd_err},
};

moqtrun_ctl_fn moqtrun_ctl_lookup(u64 type) {
  for (usz i = 0; i < MOQTRUN_CTL_TABLE_N; i++) {
    if (moqtrun_ctl_table[i].type == type) {
      return moqtrun_ctl_table[i].fn;
    }
  }
  return moqtrun_dispatch_not_supported;
}

/* Closes p's session with code, after which nothing more is sent on it;
 * 0 when the io table has no close_session. */
int moqtrun_peer_close(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code) {
  if (!hub->io.close_session) {
    return 0;
  }
  hub->io.close_session(p->wt, code, wired_span_of(0, 0));
  p->closing = 1;
  return 1;
}

/* Closes p's session with code. Every later byte of the stream being
 * handled is discarded (its skip never runs out). An io table without
 * close_session skips the message by its Length instead and keeps the
 * stream alive. */
void moqtrun_close_with(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code) {
  wired_moqtrun_ctl_asm* a = moqtrun_cur_asm(p);
  if (!moqtrun_peer_close(hub, p, code)) {
    return;
  }
  a->at   = a->n;
  a->skip = (usz)-1;
}

/* draft SS10: an unknown message type MUST close the session; SS3.5
 * PROTOCOL_VIOLATION is the code (moqsess EV_MALFORMED_CTRL). */
void moqtrun_dispatch_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_sess_fault(hub, p, MOQSESS_EV_MALFORMED_CTRL);
}

/* draft-19 3.3: a request stream whose first message is no request type
 * closes the session PROTOCOL_VIOLATION (moqsess EV_BAD_FIRST). */
void moqtrun_dispatch_bad_first(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_sess_fault(hub, p, MOQSESS_EV_BAD_FIRST);
}

/* A message longer than WIRED_MOQTRUN_CTL_MSG_MAX: the peer broke no
 * rule, the limit is ours, so SS3.5 INTERNAL_ERROR is the code. */
void moqtrun_dispatch_over_cap(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR);
}

moqtrun_ctl_fn moqtrun_ctl_route(int peek, u64 type) {
  if (peek == MOQCTL_UNKNOWN_TYPE) {
    return moqtrun_dispatch_close;
  }
  if (peek == MOQTRUN_ASM_OVER_CAP) {
    return moqtrun_dispatch_over_cap;
  }
  return moqtrun_ctl_lookup(type);
}
