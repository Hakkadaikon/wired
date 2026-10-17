#include "app/moqt/run/moqtrun_impl.h"

static wired_moqtrun_fetch* moqtrun_upf_reset_slot(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid);
static void moqtrun_upf_detach_one(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const wired_wt_session* s);
static int moqtrun_upf_hub_owned(const wired_moqt_hub* hub, wired_span name);
static int moqtrun_upf_nt_routable(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqtrun_key k);
static int moqtrun_upf_ft0(const moqctl_params* params);
static int moqtrun_upf_nt_askable(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqtrun_key k);

/* The upstream reset (or stopped) one of a leg's streams: the request is
 * cancelled and the leg failed (draft-22 3.2.4). */
static wired_moqtrun_fetch* moqtrun_upf_reset_slot(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  wired_moqtrun_fetch* d = moqtrun_upf_by_live_data(hub, s, sid);
  if (!d) {
    return moqtrun_upf_by_req(hub, s, sid);
  }
  d->up_data_end = 1; /* nothing more comes on it: no STOP_SENDING */
  return d;
}

void moqtrun_upf_on_reset(wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 sid) {
  wired_moqtrun_fetch* f = moqtrun_upf_reset_slot(hub, p->wt, sid);
  if (f) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
  }
}

/* Session s is closing: every leg to it ends now with no io toward it. A
 * FETCH still unanswered is refused; anything else is handed to the cache
 * side, served from the next tick -- a fill of s's own track is reset
 * INTERNAL_ERROR right after (moqtrun_fills_upstream_gone) instead. */
static void moqtrun_upf_detach_one(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const wired_wt_session* s) {
  if (f->up_wt == s) {
    f->up_data_open = 0; /* s's stream ids end with it */
  }
  if (!moqtrun_upf_leg_to(f, s)) {
    return;
  }
  moqtrun_upf_drop(hub, f, MOQTRUN_UPF_IO_NONE);
  moqtrun_upf_failed(hub, f, MOQCTL_ERR_INTERNAL_ERROR, 0);
}

void moqtrun_upf_detach(wired_moqt_hub* hub, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    moqtrun_upf_detach_one(hub, &hub->fetches[i], s);
  }
}

/* What f keeps is fed again: a payload the transport refused goes out
 * once it takes it (a torn head just waits on). */
void moqtrun_upf_retry(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (hub->upf_owner != f) {
    return;
  }
  moqtrun_upf_feed(
      hub, moqtrun_find_by_wt(hub, f->up_wt), f, wired_span_of(hub->upf_buf, 0),
      f->up_data_end);
}

/* A leg past its budget fails (9.20.5) -- one still waiting on a refused
 * payload resets the downstream stream (moqtrun_upf_no_window); else what
 * it keeps is retried. 1 while f had a leg: the tick does nothing else
 * for it. */
int moqtrun_upf_tick(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (!moqtrun_upf_live(f)) {
    return 0;
  }
  if (hub->live.last_now_ms >= f->up_deadline_ms) {
    f->up_tmo = 1;
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQTRUN_ERR_TIMEOUT);
  } else {
    moqtrun_upf_retry(hub, f);
  }
  return 1;
}

/* ----- a FETCH of a track the hub does not hold ----- */

static int moqtrun_upf_hub_owned(const wired_moqt_hub* hub, wired_span name) {
  return moqtrun_track_name_matches(&hub->blob_track, name) ||
         moqtrun_track_name_matches(&hub->live.track, name);
}

/* Only a FETCH on a request stream (answered there later), of a name the
 * hub could key and not one of its own tracks, goes upstream. */
static int moqtrun_upf_nt_routable(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqtrun_key k) {
  return p->req && !moqtrun_key_oversized(k) &&
         !moqtrun_upf_hub_owned(hub, k.name);
}

static int moqtrun_upf_ft0(const moqctl_params* params) {
  const moqctl_param* ft =
      moqctl_params_find(params, MOQCTL_PARAM_FILL_TIMEOUT);
  return ft && ft->vi == 0;
}

static int moqtrun_upf_nt_askable(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqtrun_key k) {
  return moqtrun_upf_nt_routable(hub, p, k) &&
         moqtrun_up_announcer(hub, p->wt, k) != 0;
}

/* DOES_NOT_EXIST with nobody to ask (no publisher, 10.2.6), TIMEOUT when
 * FILL_TIMEOUT 0 forbids waiting (9.20.5). */
u64 moqtrun_upf_nt_refusal(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* p,
    const moqfetch_req*       m,
    moqtrun_key               k) {
  if (!moqtrun_upf_nt_askable(hub, p, k)) {
    return MOQCTL_ERR_DOES_NOT_EXIST;
  }
  return moqtrun_upf_ft0(&m->params) ? MOQTRUN_ERR_TIMEOUT : MOQTRUN_REQ_ACCEPT;
}
