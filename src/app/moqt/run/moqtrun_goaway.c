#include "app/moqt/run/moqtrun_impl.h"

static moqtrun_goaway_take_fn moqtrun_goaway_decoder(int ver);
static int                    moqtrun_goaway_bad(
    wired_moqtrun_peer* p, wired_span body, moqctl_goaway* g);
static int moqtrun_goaway_rid_bad(
    const wired_moqtrun_peer* p, const moqctl_goaway* g);
static u32 moqtrun_goaway_close(wired_moqtrun_peer* p, wired_span body);
static u32 moqtrun_setup_opt_bad(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    const moqctl_setup*       m);

void moqtrun_subtracks_pub_reset(wired_moqt_hub* hub, wired_moqtrun_req* q) {
  if (q->opened) {
    hub->io.stream_reset(q->wt, q->stream_id, MOQTRUN_RESET_INTERNAL_ERROR);
  }
  q->in_use = 0;
}

void moqtrun_subtracks_track_gone(wired_moqt_hub* hub, u64 tag) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_subtracks_pub_of_tag(&hub->reqs[i], tag)) {
      moqtrun_subtracks_pub_reset(hub, &hub->reqs[i]);
    }
  }
}

void moqtrun_dispatch_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtrun_handle_publish(hub, p, peer_idx, body);
}

void moqtrun_dispatch_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtrun_handle_subscribe(hub, p, peer_idx, body);
}

void moqtrun_dispatch_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtrun_handle_fetch(hub, p, peer_idx, body);
}

void moqtrun_dispatch_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)peer_idx;
  (void)body;
  moqtrun_handle_not_supported(p);
}

/* draft-18 SS10.4: a control-stream GOAWAY ends with a Request ID. */
static moqtrun_goaway_take_fn moqtrun_goaway_decoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_GOAWAY_REQID) ? moqctl_goaway18_take
                                                      : moqctl_goaway_take;
}

/* draft-ietf-moq-transport-19 10.4: a GOAWAY on the control stream must
 * be well formed in p's draft, carry no New Session URI (the hub is the
 * server), and be the session's first. */
static int moqtrun_goaway_bad(
    wired_moqtrun_peer* p, wired_span body, moqctl_goaway* g) {
  usz off = 0;
  if (moqtrun_goaway_decoder(p->ver)(body, &off, g) != MOQCTL_OK ||
      g->new_session_uri.n) {
    return 1;
  }
  return moqsess_step(&p->sess, MOQSESS_EV_RECV_GOAWAY) != MOQSESS_CLOSE_NONE;
}

/* draft-18 SS10.4: the Request ID names one of the hub's own Request IDs,
 * which are odd (server); the wrong parity is INVALID_REQUEST_ID. */
static int moqtrun_goaway_rid_bad(
    const wired_moqtrun_peer* p, const moqctl_goaway* g) {
  return (moqver_caps(p->ver) & MOQVER_CAP_GOAWAY_REQID) &&
         !(g->request_id & 1);
}

/* Session close code a control-stream GOAWAY calls for; 0 for none. */
static u32 moqtrun_goaway_close(wired_moqtrun_peer* p, wired_span body) {
  moqctl_goaway g = {0};
  if (moqtrun_goaway_bad(p, body, &g)) {
    return WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  }
  return moqtrun_goaway_rid_bad(p, &g) ? WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID
                                       : 0;
}

/* A GOAWAY on a request stream asks to migrate that one request; the
 * route already refuses a second one, and the hub opens no requests to
 * move. One on the control stream is recorded, a bad one closes the
 * session with PROTOCOL_VIOLATION. */
void moqtrun_dispatch_goaway(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  if (p->req) {
    return;
  }
  u32 code = moqtrun_goaway_close(p, body);
  if (code) {
    moqtrun_close_with(hub, p, code);
  }
}

/* draft-19 3.3: one control stream per peer -- a 2nd one (or a 2nd
 * SETUP) closes the session with PROTOCOL_VIOLATION. */
void moqtrun_second_ctl(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  moqtrun_sess_fault(hub, p, MOQSESS_EV_SECOND_CTRL);
}

/* A SETUP after one was already accepted, or on a stream other than the
 * accepted client control stream. */
int moqtrun_setup_second(const wired_moqtrun_peer* p) {
  return p->setup_recv ||
         (p->peer_ctl_set && p->peer_ctl_stream_id != p->rx_sid);
}

/* PATH/AUTHORITY (-18/-19 10.3.1.1-2, -22 9.1.1-2): over WebTransport
 * either one is a close (INVALID_PATH / INVALID_AUTHORITY); on raw QUIC a
 * well-formed value is accepted unless hub->raw_policy refuses it, a
 * malformed one closes MALFORMED_PATH / MALFORMED_AUTHORITY. */
static u32 moqtrun_setup_opt_bad(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    const moqctl_setup*       m) {
  return moqraw_setup_verdict(p->raw, m, &hub->raw_policy);
}

/* Close code a client SETUP body calls for; 0 = accept (*m decoded). */
u32 moqtrun_setup_take_code(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    wired_span                body,
    moqctl_setup*             m) {
  usz off = 0;
  int r   = moqctl_setup_take(body, &off, m);
  if (r == MOQCTL_PARAMS_KVFMT) {
    return (u32)MOQCTL_CLOSE_KVFMT_ERROR;
  }
  if (r != MOQCTL_OK) {
    return WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION;
  }
  return moqtrun_setup_opt_bad(hub, p, m);
}
