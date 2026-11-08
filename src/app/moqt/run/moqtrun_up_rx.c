#include "app/moqt/run/moqtrun_impl.h"

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
static void moqtrun_up_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u);
static void moqtrun_up_on_fin(wired_moqt_hub* hub, wired_moqtrun_up* u);

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
  while (moqtrun_up_pop(hub, pp, u, &type, &body)) {
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
