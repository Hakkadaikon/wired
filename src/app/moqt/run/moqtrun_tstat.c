#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_fetch_auth_refused(
    const wired_moqt_hub* hub, const moqfetch_req* m);
static u64 moqtrun_fetch_ftn_verdict(
    const wired_moqt_hub* hub, const moqfetch_req* m);
static u64 moqtrun_fetch_name_verdict(
    const wired_moqt_hub* hub, const moqfetch_req* m);
static u64 moqtrun_fetch_verdict(
    const wired_moqt_hub* hub, const moqfetch_req* m);
static void moqtrun_fetch_arr_drop(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, const wired_wt_session* s);
static wired_moqtrun_track* moqtrun_tstat_track(
    wired_moqt_hub* hub, const moqctl_ftn* f);
static u64 moqtrun_tstat_verdict(
    const wired_moqt_hub*      hub,
    const moqctl_subscribe*    m,
    const wired_moqtrun_track* t);
static void moqtrun_tstat_answer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body);

/* draft-22 7.4: a relay authorizes every request; the hub's SUBSCRIBE
 * authorizer judges a FETCH's Full Track Name too. */
static int moqtrun_fetch_auth_refused(
    const wired_moqt_hub* hub, const moqfetch_req* m) {
  return hub->authorize_subscribe &&
         !hub->authorize_subscribe(
             hub->authorize_ctx, &m->track, moqtrun_auth_token_of(&m->params));
}

/* A Standalone Fetch's name: a reserved namespace is DOES_NOT_EXIST
 * (2.4.2/2.4.3), then authorization. */
static u64 moqtrun_fetch_ftn_verdict(
    const wired_moqt_hub* hub, const moqfetch_req* m) {
  if (moqtrun_ns_reserved(&m->track.ns)) {
    return MOQCTL_ERR_DOES_NOT_EXIST;
  }
  return moqtrun_fetch_auth_refused(hub, m) ? MOQCTL_ERR_UNAUTHORIZED
                                            : MOQTRUN_REQ_ACCEPT;
}

/* A Joining Fetch names its subscription, authorized already. */
static u64 moqtrun_fetch_name_verdict(
    const wired_moqt_hub* hub, const moqfetch_req* m) {
  return m->is_joining ? MOQTRUN_REQ_ACCEPT : moqtrun_fetch_ftn_verdict(hub, m);
}

/* What a FETCH is refused before any routing, else MOQTRUN_REQ_ACCEPT:
 * Range Filters first (INVALID_FILTER), then its name. */
static u64 moqtrun_fetch_verdict(
    const wired_moqt_hub* hub, const moqfetch_req* m) {
  if (moqtrun_rngf_refusal(&m->params) != MOQTRUN_REQ_ACCEPT) {
    return MOQCTL_ERR_INVALID_FILTER;
  }
  return moqtrun_fetch_name_verdict(hub, m);
}

/* draft 10.12 FETCH. A body that fails to decode is a malformed control
 * message: the session closes, like a malformed REQUEST_UPDATE. */
void moqtrun_handle_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqfetch_req m;
  if (moqtrun_fetch_take(p, body, &m) != MOQCTL_OK) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  u64 code = moqtrun_fetch_verdict(hub, &m);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_fetch_route(hub, p, peer_idx, &m);
}

static void moqtrun_fetch_arr_drop(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (arr[i].wt == s) {
      moqtrun_fetch_free(hub, &arr[i]);
    }
  }
}

/* A closed session's fetches end: nothing more is sent for them. */
void moqtrun_fetches_drop(wired_moqt_hub* hub, wired_wt_session* s) {
  moqtrun_fetch_arr_drop(hub, hub->fetches, s);
  moqtrun_fetch_arr_drop(hub, hub->fetch_waits, s);
}

/* ===================== TRACK_STATUS (draft 10.14) ===================== */

/* The track a SUBSCRIBE for f would reach (moqtrun_route_subscribe's
 * order: the hub's own tracks first), else 0. */
static wired_moqtrun_track* moqtrun_tstat_track(
    wired_moqt_hub* hub, const moqctl_ftn* f) {
  u8 ns_buf[WIRED_MOQTRUN_MAX_NS];
  if (moqtrun_track_name_matches(&hub->blob_track, f->name)) {
    return &hub->blob_track;
  }
  if (moqtrun_track_name_matches(&hub->live.track, f->name)) {
    return &hub->live.track;
  }
  return moqtrun_find_published_track(hub, moqtrun_key_of(f, ns_buf));
}

/* Treated as a SUBSCRIBE that creates no state and sends no Objects:
 * TRACK_STATUS_OK carries what SUBSCRIBE_OK would (the Largest Location),
 * and the request, answered without going live, is FINed. */
static u64 moqtrun_tstat_verdict(
    const wired_moqt_hub*      hub,
    const moqctl_subscribe*    m,
    const wired_moqtrun_track* t) {
  u64 code = MOQCTL_ERR_DOES_NOT_EXIST;
  if (!t) {
    return code;
  }
  if (moqtrun_subscribe_refused(hub, m, &code)) {
    return code;
  }
  return MOQTRUN_REQ_ACCEPT;
}

static void moqtrun_tstat_answer(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body) {
  moqctl_subscribe m;
  if (!moqtrun_take_tok_or_close(
          hub, p, moqtstat_take(p->ver, body, &m), &m.params)) {
    return;
  }
  wired_moqtrun_track* t    = moqtrun_tstat_track(hub, &m.name);
  u64                  code = moqtrun_tstat_verdict(hub, &m, t);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  /* draft-18 10.14: "the same parameters and Track Properties it would
   * have set in a SUBSCRIBE_OK". */
  moqtrun_queue_request_ok_props(p, t, moqtrun_track_props(t));
}

/* TRACK_STATUS is the first and only message of a new request stream
 * (10.14): on the control stream it is NOT_SUPPORTED, like the namespace
 * requests. */
void moqtrun_handle_tstat(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  if (!p->req) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  moqtrun_tstat_answer(hub, p, body);
}
