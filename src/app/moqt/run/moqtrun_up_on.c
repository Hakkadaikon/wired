#include "app/moqt/run/moqtrun_impl.h"

static u64 moqtrun_up_route_type(const wired_moqtrun_up* u, u64 type);
static int moqtrun_up_was_on(
    const wired_moqtrun_up* u, const wired_wt_session* s, u64 sid);
static wired_moqtrun_up* moqtrun_up_was_of(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
static int moqtrun_up_rx_on(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_up*   u,
    wired_span          data,
    int                 fin);
static int moqtrun_up_first_answer(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    moqsub_event        ev);
static void moqtrun_up_on_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body);
static void moqtrun_up_on_error(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body);
static void moqtrun_up_on_done(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body);
static void moqtrun_up_on_upd_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body);
static void moqtrun_up_on_reqerr(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body);
static void moqtrun_up_on_update(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body);
static void moqtrun_up_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    u64                 type,
    wired_span          body);
static void moqtrun_up_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u);
static void moqtrun_up_on_fin(wired_moqt_hub* hub, wired_moqtrun_up* u);

/* draft-19 5.1 (draft-18 5.1, draft-22 3.1): "A publisher MUST send
 * exactly one SUBSCRIBE_OK or REQUEST_ERROR in response to a SUBSCRIBE.
 * ... The peer SHOULD close the session with a protocol error if it
 * receives more than one." ev steps u's moqsub; 1 when it is the first
 * answer; a second one (moqsub's session_fault) closes the session
 * PROTOCOL_VIOLATION. */
static int moqtrun_up_first_answer(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    moqsub_event        ev) {
  if (moqsub_step(&u->sub, ev)) {
    return 1;
  }
  if (u->sub.session_fault) {
    moqtrun_close_cc(hub, pp, MOQTRUN_CC_UNEXPECTED);
  }
  return 0;
}

/* A reply that fails to decode closes the session PROTOCOL_VIOLATION
 * (moqtrun_take_or_close), as does a second answer
 * (moqtrun_up_first_answer). */
static void moqtrun_up_on_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  usz                 off = 0;
  moqctl_subscribe_ok m;
  if (!moqtrun_up_first_answer(hub, pp, u, MOQSUB_EV_OK)) {
    return;
  }
  if (!moqtrun_take_or_close(
          hub, pp, moqctl_subscribe_ok_take(pp->ver, body, &off, &m))) {
    return;
  }
  moqtrun_up_claim(hub, pp, u, &m);
}

/* REQUEST_ERROR: each waiter gets the publisher's code, re-spelled for
 * its own draft (moqtrun_send_request_error); the request is complete,
 * so the hub's side FINs (draft-19 3.3.2). */
static void moqtrun_up_on_error(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  moqctl_request_error e;
  if (!moqtrun_up_first_answer(hub, pp, u, MOQSUB_EV_ERROR)) {
    return;
  }
  if (!moqtrun_reqerr_take(hub, pp, body, &e)) {
    return;
  }
  /* draft-23 9.4.2.2: UNSUPPORTED_EXTENSION goes on with the
   * UNSUPPORTED_PROPERTY details received */
  bytes_memcpy(hub->unsupp, e.unsupported, e.n_unsupported * sizeof(u64));
  hub->unsupp_n = e.n_unsupported;
  moqtrun_up_failed(hub, u, e.error_code);
  hub->unsupp_n = 0;
}

/* PUBLISH_DONE: relayed like a PUBLISHer's (moqtrun_pubdone_arm, each
 * subscription's own Stream Count); the track's retirement then ends
 * the hub's side (moqtrun_up_end). */
static void moqtrun_up_on_done(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  wired_moqtrun_track* t = moqtrun_up_track(pp, u);
  if (!t) {
    return;
  }
  u->done = 1;
  moqtrun_pubdone_arm(hub, pp, t, body);
}

/* The publisher reset the hub's SUBSCRIBE stream: the request is
 * cancelled (draft-22 6.4.2.3). Waiters are refused INTERNAL_ERROR; an
 * Established track ends for its subscribers (PUBLISH_DONE) and retires.
 * The hub resets its own still-open direction. */
void moqtrun_up_on_reset(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 stream_id) {
  wired_moqtrun_up*    u = moqtrun_up_of_stream(hub, p->wt, stream_id);
  wired_moqtrun_track* t;
  if (!u) {
    return;
  }
  t = moqtrun_up_track(p, u);
  if (t) {
    moqtrun_track_ended(hub, t);
    moqtrun_track_retire(hub, t);
  }
  hub->io.stream_reset(u->wt, u->stream_id, MOQTRUN_RESET_CANCELLED);
  moqtrun_up_refused(hub, u, MOQCTL_ERR_INTERNAL_ERROR);
}

/* REQUEST_OK answering one of the hub's REQUEST_UPDATEs (moqtrun_ngr.c). */
static void moqtrun_up_on_upd_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  (void)hub;
  (void)pp;
  (void)body;
  u->upd_out -= (u8)(u->upd_out != 0);
}

/* REQUEST_ERROR: an outstanding REQUEST_UPDATE's answer (its
 * NEW_GROUP_REQUEST no longer outstanding, draft-18 10.2.13), else the
 * SUBSCRIBE's. */
static void moqtrun_up_on_reqerr(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  if (!u->upd_out) {
    moqtrun_up_on_error(hub, pp, u, body);
    return;
  }
  u->upd_out--;
  u->ngr.out = 0;
}

/* draft-23 9.5: the hub sent this SUBSCRIBE, so a REQUEST_UPDATE from
 * its receiver is unexpected and closes the session (d22 9.5 / d19 10.9
 * PROTOCOL_VIOLATION; d18 has no such sentence and ignores it). */
static void moqtrun_up_on_update(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  (void)u;
  (void)body;
  if (moqver_caps(pp->ver) & MOQVER_CAP_UPDATE_STRAY_CLOSE) {
    moqtrun_close_cc(hub, pp, MOQTRUN_CC_UNEXPECTED);
  }
}

/* What a publisher sends on a SUBSCRIBE's stream (draft-19 10.7, 10.8,
 * 10.9, 10.11); anything else is ignored. */
static const struct {
  u64           type;
  moqtrun_up_fn fn;
} MOQTRUN_UP_ROUTES[] = {
    {MOQCTL_T_SUBSCRIBE_OK, moqtrun_up_on_ok},
    {MOQCTL_T_REQUEST_ERROR, moqtrun_up_on_reqerr},
    {MOQCTL_T_REQUEST_OK, moqtrun_up_on_upd_ok},
    {MOQCTL_T_PUBLISH_DONE, moqtrun_up_on_done},
    {MOQTSTAT_T_REQUEST_UPDATE, moqtrun_up_on_update},
};

/* The route of a message of type on u's stream: once u ended it is
 * still a request stream (draft-23 9.5) where only a REQUEST_UPDATE
 * still counts, anything else routes nowhere (0). */
static u64 moqtrun_up_route_type(const wired_moqtrun_up* u, u64 type) {
  return u->in_use || type == MOQTSTAT_T_REQUEST_UPDATE ? type : 0;
}

static void moqtrun_up_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    u64                 type,
    wired_span          body) {
  type = moqtrun_up_route_type(u, type);
  for (usz i = 0; i < sizeof MOQTRUN_UP_ROUTES / sizeof MOQTRUN_UP_ROUTES[0];
       i++) {
    if (MOQTRUN_UP_ROUTES[i].type == type) {
      MOQTRUN_UP_ROUTES[i].fn(hub, pp, u, body);
    }
  }
}

/* 1 when u holds a complete message for the route table: a known Type,
 * implemented or not (REQUEST_UPDATE classifies as the latter). */
static int moqtrun_up_pop(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    u64*                type,
    wired_span*         body) {
  int r = moqtrun_asm_pop(hub, pp, &u->in, type, body);
  return r == MOQCTL_OK || r == MOQCTL_KNOWN_UNIMPLEMENTED;
}

static void moqtrun_up_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u) {
  u64        type = 0;
  wired_span body = {0, 0};
  while (!pp->closing && moqtrun_up_pop(hub, pp, u, &type, &body)) {
    moqtrun_up_route(hub, pp, u, type, body);
  }
}

/* data into u's reassembly, drained after each push (a message past the
 * inline buffer moves to a pool buffer between them). */
static void moqtrun_up_feed(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          data) {
  while (moqtrun_asm_feed(&u->in, &data)) {
    moqtrun_up_drain(hub, pp, u);
  }
}

/* draft-19 3.3.2: the publisher FINned its side with no response -- the
 * request failed, its waiters answered as for a REQUEST_ERROR. */
static void moqtrun_up_on_fin(wired_moqt_hub* hub, wired_moqtrun_up* u) {
  if (!u->in_use || u->track_tag) {
    return;
  }
  moqtrun_up_failed(hub, u, MOQCTL_ERR_INTERNAL_ERROR);
}

/* The waiters' answers go out, and their streams settle, in the same
 * dispatch (moqtrun_reqs_tick). A FIN after SUBSCRIBE_OK ends nothing
 * (draft-19 3.3.2). */
static int moqtrun_up_was_on(
    const wired_moqtrun_up* u, const wired_wt_session* s, u64 sid) {
  return u->wt == s && u->stream_id == sid;
}

/* The entry whose SUBSCRIBE ran on sid, ended or not: it keeps the id
 * until it is claimed again. */
static wired_moqtrun_up* moqtrun_up_was_of(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_was_on(&hub->ups[i], s, sid)) {
      return &hub->ups[i];
    }
  }
  return 0;
}

static int moqtrun_up_rx_on(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_up*   u,
    wired_span          data,
    int                 fin) {
  if (!u) {
    return 0;
  }
  moqtrun_up_feed(hub, p, u, data);
  if (fin) {
    moqtrun_up_on_fin(hub, u);
  }
  moqtrun_reqs_tick(hub);
  return 1;
}

int moqtrun_up_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  return moqtrun_up_rx_on(
      hub, p, moqtrun_up_of_stream(hub, p->wt, stream_id), data, fin);
}

/* As moqtrun_up_rx on a stream whose SUBSCRIBE ended: still a request
 * stream (draft-23 9.5). Asked only once no live request owns sid, so
 * an entry kept from an earlier session on the same session object
 * never takes a live stream. */
int moqtrun_up_rx_ended(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  return moqtrun_up_rx_on(
      hub, p, moqtrun_up_was_of(hub, p->wt, stream_id), data, fin);
}
