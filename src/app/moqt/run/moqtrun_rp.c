#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_sw_done(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si);
static void moqtrun_sw_stop_streams(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si);
static void moqtrun_sw_remember(
    wired_moqt_hub* hub, const wired_moqtrun_sub* s);
static int moqtrun_rp_matches(const wired_moqtrun_rdv* r, moqtrun_key k);

/* A fill's stream was granted: the PUBLISH_DONE deferred while it was
 * held goes out once no held fill of its subscription remains. */
void moqtrun_fill_opened(wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  if (!f->is_fill) {
    return;
  }
  wired_moqtrun_req* q = moqtrun_fill_owner_req(hub, f);
  if (!moqtrun_done_due(hub, f, q)) {
    return;
  }
  moqtrun_done_emit(
      moqtrun_find_by_wt(hub, f->wt), q, q->done_status, q->done_count);
  q->done_pending = 0;
}

/* The request stream carrying sub slot si of t, else 0. */
wired_moqtrun_req* moqtrun_sub_slot_req(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, usz si) {
  const wired_moqtrun_sub* s = &t->subs[si];
  /* an inactive slot's session_idx is unset: never index peers[] by it */
  if (!s->active) {
    return 0;
  }
  return moqtrun_sub_req(hub, &hub->peers[s->session_idx], s->request_id);
}

/* Ends active sub slot si of t: PUBLISH_DONE status when it is held on a
 * request stream; one without (control stream) still stops, its streams
 * reset (10.11), so it never outlives its track. */
void moqtrun_sub_done_slot(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u64 status) {
  wired_moqtrun_sub* s = &t->subs[si];
  wired_moqtrun_req* q = moqtrun_sub_slot_req(hub, t, si);
  if (q) {
    moqtrun_sub_done(hub, &hub->peers[s->session_idx], q, t, s, status);
  } else if (s->active) {
    moqtrun_sub_stop(hub, t, s, moqtrun_done_reset_code(status));
  }
}

/* ===== SWITCH_FROM (moqtswitch.c): the hub actions it decides ===== */

/* Ends slot si with PUBLISH_DONE "switched" on its request stream; a
 * subscription without one (control stream) just stops. */
static void moqtrun_sw_done(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si) {
  moqtrun_sub_done_slot(hub, t, si, MOQTSW_DONE_SWITCHED);
}

static void moqtrun_sw_stop_streams(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si) {
  moqtrun_sub_reset_streams(hub, t, si, MOQTRUN_RESET_CANCELLED);
  moqtrun_relays_clear_sub(hub, t, si);
}

static void moqtrun_sw_remember(
    wired_moqt_hub* hub, const wired_moqtrun_sub* s) {
  moqtrun_upd_remember(&hub->peers[s->session_idx], s);
}

static const moqtsw_ops MOQTRUN_SW_OPS = {
    moqtrun_sub_by_rid, moqtrun_sw_done, moqtrun_sw_stop_streams,
    moqtrun_sw_remember, moqtrun_sub_resolve};

const moqtsw_ops* moqtrun_sw_ops(void) { return &MOQTRUN_SW_OPS; }

/* Bit of s's peer slot; 0 for a session gone. */
u64 moqtrun_rp_bit(wired_moqt_hub* hub, wired_wt_session* s) {
  wired_moqtrun_peer* p = moqtrun_find_by_wt(hub, s);
  return p ? (u64)1 << (usz)(p - hub->peers) : 0;
}

static int moqtrun_rp_matches(const wired_moqtrun_rdv* r, moqtrun_key k) {
  return moqtrun_rdv_matches(r, k) && r->repath;
}

/* Sessions not to ask for k: the ones tried in this wait. A waiter's own
 * session is skipped only for that waiter (moqtrun_up_covers): it is
 * another waiting session's path. */
u64 moqtrun_rp_skip(wired_moqt_hub* hub, moqtrun_key k) {
  u64 m = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rp_matches(&hub->rdv[i], k)) {
      m |= hub->rdv[i].tried;
    }
  }
  return m;
}

/* The sessions waiting for a new path for k. */
u64 moqtrun_rp_waiters(wired_moqt_hub* hub, moqtrun_key k) {
  u64 m = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rp_matches(&hub->rdv[i], k)) {
      m |= moqtrun_rp_bit(hub, hub->rdv[i].wt);
    }
  }
  return m;
}

/* s was asked for k: every wait for k counts it tried. */
void moqtrun_rp_mark(wired_moqt_hub* hub, moqtrun_key k, wired_wt_session* s) {
  u64 bit = moqtrun_rp_bit(hub, s);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rp_matches(&hub->rdv[i], k)) {
      hub->rdv[i].tried |= bit;
    }
  }
}
