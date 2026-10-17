#include "app/moqt/run/moqtrun_impl.h"

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
static void moqtrun_up_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    u64                 type,
    wired_span          body);
static void moqtrun_up_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u);

/* A reply that fails to decode closes the session PROTOCOL_VIOLATION
 * (moqtrun_take_or_close); a second SUBSCRIBE_OK is ignored. */
static void moqtrun_up_on_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    wired_span          body) {
  usz                 off = 0;
  moqctl_subscribe_ok m;
  if (u->track_tag) {
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
  usz                  off = 0;
  moqctl_request_error e;
  if (u->track_tag) {
    return;
  }
  if (!moqtrun_take_or_close(
          hub, pp, moqctl_request_error_take(body, &off, &e))) {
    return;
  }
  moqtrun_up_refuse_waiters(hub, moqtrun_up_key(u), e.error_code);
  hub->io.stream_fin(u->wt, u->stream_id);
  u->in_use = 0;
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
  moqtrun_up_refuse_waiters(hub, moqtrun_up_key(u), MOQCTL_ERR_INTERNAL_ERROR);
  if (t) {
    moqtrun_track_ended(hub, t);
    moqtrun_track_retire(hub, t);
  }
  hub->io.stream_reset(u->wt, u->stream_id, MOQTRUN_RESET_CANCELLED);
  u->in_use = 0;
}

/* What a publisher sends on a SUBSCRIBE's stream (draft-19 10.7, 10.8,
 * 10.11); anything else is ignored. */
static const struct {
  u64           type;
  moqtrun_up_fn fn;
} MOQTRUN_UP_ROUTES[] = {
    {MOQCTL_T_SUBSCRIBE_OK, moqtrun_up_on_ok},
    {MOQCTL_T_REQUEST_ERROR, moqtrun_up_on_error},
    {MOQCTL_T_PUBLISH_DONE, moqtrun_up_on_done},
};

static void moqtrun_up_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    u64                 type,
    wired_span          body) {
  for (usz i = 0; i < sizeof MOQTRUN_UP_ROUTES / sizeof MOQTRUN_UP_ROUTES[0];
       i++) {
    if (MOQTRUN_UP_ROUTES[i].type == type) {
      MOQTRUN_UP_ROUTES[i].fn(hub, pp, u, body);
    }
  }
}

static void moqtrun_up_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u) {
  u64        type = 0;
  wired_span body = {0, 0};
  while (u->in_use && moqtrun_asm_pop(&u->in, &type, &body) == MOQCTL_OK) {
    moqtrun_up_route(hub, pp, u, type, body);
  }
}

/* The waiters' answers go out, and their streams settle, in the same
 * dispatch (moqtrun_reqs_tick). A FIN from the publisher ends nothing
 * (draft-19 3.3.2). */
int moqtrun_up_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data) {
  wired_moqtrun_up* u = moqtrun_up_of_stream(hub, p->wt, stream_id);
  if (!u) {
    return 0;
  }
  moqtrun_asm_push(&u->in, &data);
  moqtrun_up_drain(hub, p, u);
  moqtrun_reqs_tick(hub);
  return 1;
}
