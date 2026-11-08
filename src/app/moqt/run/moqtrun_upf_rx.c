#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_on_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid);
static int moqtrun_upf_fin_unanswered(const wired_moqtrun_fetch* f, int fin);
static int moqtrun_upf_was_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid);
static wired_moqtrun_fetch* moqtrun_upf_was_by_req(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
static int moqtrun_upf_rx_on(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           data,
    int                  fin);

static int moqtrun_upf_was_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid) {
  return f->up_wt == s && f->up_req_sid == sid;
}

static int moqtrun_upf_on_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid) {
  return moqtrun_upf_live(f) && moqtrun_upf_was_req(f, s, sid);
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

/* The slot whose leg ran on sid, ended or not: it keeps the id until it
 * runs another leg. */
static wired_moqtrun_fetch* moqtrun_upf_was_by_req(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_was_req(&hub->fetches[i], s, sid)) {
      return &hub->fetches[i];
    }
  }
  return 0;
}

static int moqtrun_upf_fin_unanswered(const wired_moqtrun_fetch* f, int fin) {
  return fin && f->up_state == WIRED_MOQTRUN_UPF_SENT;
}

/* data into f's reassembly, drained after each push (a message past the
 * inline buffer moves to a pool buffer between them). */
static void moqtrun_upf_rx_feed(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           data) {
  while (moqtrun_asm_feed(&moqtrun_upf_leg_of(hub, f)->in, &data)) {
    moqtrun_upf_drain(hub, pp, f);
  }
}

/* Replies on one of the hub's upstream FETCH request streams; the
 * answers they cause go out in the same dispatch. 1 when sid is one. A
 * FIN with no FETCH_OK yet fails the request (draft-19 3.3.2) as a
 * REQUEST_ERROR would. */
static int moqtrun_upf_rx_on(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           data,
    int                  fin) {
  if (!f) {
    return 0;
  }
  moqtrun_upf_rx_feed(hub, pp, f, data);
  if (moqtrun_upf_fin_unanswered(f, fin)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_FIN, MOQCTL_ERR_INTERNAL_ERROR);
  }
  moqtrun_reqs_tick(hub);
  return 1;
}

int moqtrun_upf_rx(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  return moqtrun_upf_rx_on(
      hub, pp, moqtrun_upf_by_req(hub, pp->wt, sid), data, fin);
}

/* As moqtrun_upf_rx on a stream whose leg ended: still a request stream
 * (draft-23 9.5). Asked only once no live request owns sid, so a slot
 * kept from an earlier session on the same session object never takes
 * a live stream. */
int moqtrun_upf_rx_ended(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  return moqtrun_upf_rx_on(
      hub, pp, moqtrun_upf_was_by_req(hub, pp->wt, sid), data, fin);
}

/* ----- the leg's other ends ----- */

wired_moqtrun_fetch* moqtrun_upf_by_live_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  wired_moqtrun_fetch* f = moqtrun_upf_by_data(hub, s, sid);
  return f && moqtrun_upf_live(f) ? f : 0;
}
