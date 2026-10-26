#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upf_on_err(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           body);
static void moqtrun_upf_reply(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    u64                  type,
    wired_span           body);
static void moqtrun_upf_goaway(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    int                  seen);
static int moqtrun_upf_route(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    u64                  type,
    wired_span           body,
    int                  goaways);
static int  moqtrun_upf_popped(int r);
static void moqtrun_upf_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_fetch* f);
static int moqtrun_upf_on_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid);

/* REQUEST_ERROR: the request is complete (the hub FINs its side); a FETCH
 * still unanswered gets it as is -- code, Retry Interval, and for
 * REDIRECT the Redirect (9.4, 9.4.1) -- anything else the cache side. */
static void moqtrun_upf_on_err(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           body) {
  moqctl_request_error e;
  if (!moqtrun_reqerr_take(hub, pp, body, &e)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_NONE, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_upf_drop(hub, f, MOQTRUN_UPF_IO_FIN);
  moqtrun_upf_failed_with(hub, f, &e, 1);
}

static const struct {
  u64            type;
  moqtrun_upf_fn fn;
} MOQTRUN_UPF_ROUTES[] = {
    {MOQFETCH_T_FETCH_OK, moqtrun_upf_on_ok},
    {MOQCTL_T_REQUEST_ERROR, moqtrun_upf_on_err},
};

static void moqtrun_upf_reply(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    u64                  type,
    wired_span           body) {
  for (usz i = 0; i < sizeof MOQTRUN_UPF_ROUTES / sizeof MOQTRUN_UPF_ROUTES[0];
       i++) {
    if (MOQTRUN_UPF_ROUTES[i].type == type) {
      MOQTRUN_UPF_ROUTES[i].fn(hub, pp, f, body);
    }
  }
}

/* GOAWAY on the request stream (9.2): the leg ends (no re-issue); a
 * second one closes the session PROTOCOL_VIOLATION. */
static void moqtrun_upf_goaway(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    int                  seen) {
  if (seen) {
    moqtrun_close_with(hub, pp, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  if (moqtrun_upf_live(f)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
  }
}

/* 1 when the message was a GOAWAY. */
static int moqtrun_upf_route(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    u64                  type,
    wired_span           body,
    int                  goaways) {
  if (type == MOQCTL_T_GOAWAY) {
    moqtrun_upf_goaway(hub, pp, f, goaways);
    return 1;
  }
  if (moqtrun_upf_live(f)) {
    moqtrun_upf_reply(hub, pp, f, type, body);
  }
  return 0;
}

/* A whole message popped: one the hub only ever receives here (FETCH_OK)
 * classifies as known but not handled on a control stream. */
static int moqtrun_upf_popped(int r) {
  return r == MOQCTL_OK || r == MOQCTL_KNOWN_UNIMPLEMENTED;
}

/* Every whole reply in f's reassembly, in order; once the leg ended only
 * a GOAWAY still counts. */
static void moqtrun_upf_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_fetch* f) {
  u64        type    = 0;
  wired_span body    = {0, 0};
  int        goaways = 0;
  while (!pp->closing && moqtrun_upf_popped(moqtrun_asm_pop(
                             &moqtrun_upf_leg_of(hub, f)->in, &type, &body))) {
    goaways += moqtrun_upf_route(hub, pp, f, type, body, goaways);
  }
}

static int moqtrun_upf_on_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid) {
  return moqtrun_upf_live(f) && f->up_wt == s && f->up_req_sid == sid;
}

wired_moqtrun_fetch* moqtrun_upf_by_req(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_on_req(&hub->fetches[i], s, sid)) {
      return &hub->fetches[i];
    }
  }
  return 0;
}

/* Replies on one of the hub's upstream FETCH request streams; the
 * answers they cause go out in the same dispatch. 1 when sid is one. */
int moqtrun_upf_rx(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, u64 sid, wired_span data) {
  wired_moqtrun_fetch* f = moqtrun_upf_by_req(hub, pp->wt, sid);
  if (!f) {
    return 0;
  }
  moqtrun_asm_push(&moqtrun_upf_leg_of(hub, f)->in, &data);
  moqtrun_upf_drain(hub, pp, f);
  moqtrun_reqs_tick(hub);
  return 1;
}

/* ----- the leg's other ends ----- */

wired_moqtrun_fetch* moqtrun_upf_by_live_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  wired_moqtrun_fetch* f = moqtrun_upf_by_data(hub, s, sid);
  return f && moqtrun_upf_live(f) ? f : 0;
}
