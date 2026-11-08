#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upf_on_err(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           body);
static u64  moqtrun_upf_route_type(const wired_moqtrun_peer* pp, u64 type);
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
static int moqtrun_upf_popped(int r);
static int moqtrun_upf_routed(const wired_moqtrun_fetch* f, u64 type);

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

/* draft-23 9.5: the hub sent this FETCH, so a REQUEST_UPDATE from its
 * receiver is unexpected and closes the session (d22 9.5 / d19 10.9
 * PROTOCOL_VIOLATION; d18 has no such sentence and ignores it). */
static void moqtrun_upf_on_update(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           body) {
  (void)f;
  (void)body;
  if (moqver_caps(pp->ver) & MOQVER_CAP_UPDATE_STRAY_CLOSE) {
    moqtrun_close_cc(hub, pp, MOQTRUN_CC_UNEXPECTED);
  }
}

static const struct {
  u64            type;
  moqtrun_upf_fn fn;
} MOQTRUN_UPF_ROUTES[] = {
    {MOQFETCH_T_FETCH_OK, moqtrun_upf_on_ok},
    {MOQCTL_T_REQUEST_ERROR, moqtrun_upf_on_err},
    {MOQTSTAT_T_REQUEST_UPDATE, moqtrun_upf_on_update},
};

/* The route of a reply's wire Type in pp's draft: the FETCH response
 * (REQUEST_OK in draft-23 9.3) routes as FETCH_OK; 0x18 is reserved
 * there (9 Table 5) and routes nowhere. */
static u64 moqtrun_upf_route_type(const wired_moqtrun_peer* pp, u64 type) {
  if (type == moqtrun_fetch_ok_type(pp->ver)) {
    return MOQFETCH_T_FETCH_OK;
  }
  return type == MOQFETCH_T_FETCH_OK ? 0 : type;
}

static void moqtrun_upf_reply(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    u64                  type,
    wired_span           body) {
  type = moqtrun_upf_route_type(pp, type);
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
    moqtrun_close_cc(hub, pp, MOQTRUN_CC_UNEXPECTED);
    return;
  }
  if (moqtrun_upf_live(f)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
  }
}

/* Once the leg ended its stream is still a request stream (draft-23 9.5):
 * only a REQUEST_UPDATE still counts. */
static int moqtrun_upf_routed(const wired_moqtrun_fetch* f, u64 type) {
  return moqtrun_upf_live(f) || type == MOQTSTAT_T_REQUEST_UPDATE;
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
  if (moqtrun_upf_routed(f, type)) {
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
 * a GOAWAY or a REQUEST_UPDATE still counts. */
void moqtrun_upf_drain(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_fetch* f) {
  u64        type    = 0;
  wired_span body    = {0, 0};
  int        goaways = 0;
  while (!pp->closing &&
         moqtrun_upf_popped(moqtrun_asm_pop(
             hub, pp, &moqtrun_upf_leg_of(hub, f)->in, &type, &body))) {
    goaways += moqtrun_upf_route(hub, pp, f, type, body, goaways);
  }
}
