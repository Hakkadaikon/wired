#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_fill_wait_put(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   rid,
    wired_moqtrun_sub*    sub,
    const moqtrun_frange* r,
    const moqfetch_fill*  fill);
static void moqtrun_fill_wait_convert(
    wired_moqt_hub* hub, wired_moqtrun_fetch* w);
static moqctl_rangeloc moqtrun_fill_rl_of(int has, const moqctl_rangeloc* rl);

static void moqtrun_fill_wait_put(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   rid,
    wired_moqtrun_sub*    sub,
    const moqtrun_frange* r,
    const moqfetch_fill*  fill) {
  wired_moqtrun_fetch* w = moqtrun_fetch_arr_slot(hub->fetch_waits);
  if (!w) {
    return;
  }
  bytes_memset(w, 0, sizeof *w);
  w->in_use     = 1;
  w->is_fill    = 1;
  w->wt         = wt;
  w->request_id = rid;
  w->owner_rid  = sub->request_id;
  w->cache_tag  = r->tag;
  w->cursor     = r->start;
  w->end        = r->end;
  w->descending = fill->descending;
  moqtrun_fsel_keep(w, sub->rngf, sub->rngf_n); /* inherited (22 3.4) */
  moqtrun_upf_budget(w, fill->has_timeout, fill->timeout_ms);
  sub->stream_count++;
}

/* A waiting fill whose serving slot came free: taken over by fetches[]
 * and the normal path (its upstream FETCH starting now if the cache lacks
 * part of it) -- or open-to-reset, for one whose upstream left while it
 * waited -- continues from there. */
static void moqtrun_fill_wait_convert(
    wired_moqt_hub* hub, wired_moqtrun_fetch* w) {
  moqtrun_frange       r = {w->cache_tag, w->cursor, w->end,   {0, 0},
                            {0, 0},       w->rngf,   w->rngf_n};
  wired_moqtrun_fetch* f = moqtrun_fetch_begin(hub, w->wt, w->request_id, &r);
  if (!f) {
    return;
  }
  moqtrun_fill_flag(hub, f, w->owner_rid, w->descending, &r);
  f->failed       = w->failed;
  f->up_budget_ms = w->up_budget_ms;
  f->up_tmo       = w->up_tmo;
  w->in_use       = 0;
  if (!f->failed) {
    moqtrun_upf_fill(hub, f, &r);
  }
}

void moqtrun_fill_waits_tick(wired_moqt_hub* hub, int descending) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_fetch_in_pass(&hub->fetch_waits[i], descending)) {
      moqtrun_fill_wait_convert(hub, &hub->fetch_waits[i]);
    }
  }
}

/* A filter as a FETCH range: no filter fills everything up to the
 * Largest Object (SS9.20.9). */
static moqctl_rangeloc moqtrun_fill_rl_of(int has, const moqctl_rangeloc* rl) {
  moqctl_rangeloc all = {MOQCTL_RSK_ABS, 0, 0, MOQCTL_REK_UNBOUNDED, 0, 0};
  return has ? *rl : all;
}

/* The fill range (SS3.4): the LOCATION_FILTER inside FILL_PARAMETERS,
 * or the subscription's own Location filter when it is omitted. */
moqctl_rangeloc moqtrun_fill_rl(
    const moqfetch_fill* fill, const wired_moqtrun_sub* sub) {
  if (fill->inherit) {
    return moqtrun_fill_rl_of(sub->has_filter, &sub->filter);
  }
  return moqtrun_fill_rl_of(fill->has_filter, &fill->range);
}

/* Opens one fill fetch stream over the resolved range r for the
 * subscription owning sub; rid is the FETCH_HEADER's Request ID (the
 * SUBSCRIBE's or REQUEST_UPDATE's that carried FILL_PARAMETERS). What the
 * cache lacks at its front is fetched upstream first (SS3.4). */
void moqtrun_fill_open(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_moqtrun_sub*    sub,
    u64                   rid,
    const moqfetch_fill*  fill,
    const moqtrun_frange* fr) {
  moqtrun_frange        r0 = *fr;
  const moqtrun_frange* r  = &r0;
  wired_moqtrun_fetch*  f;
  r0.rngf   = sub->rngf; /* the fill inherits its range filters (22 3.4) */
  r0.rngf_n = sub->rngf_n;
  f         = moqtrun_fetch_begin(hub, p->wt, rid, r);
  if (!f) {
    moqtrun_fill_wait_put(hub, p->wt, rid, sub, r, fill);
    return;
  }
  sub->stream_count++; /* PUBLISH_DONE counts fills too (10.10) */
  moqtrun_fill_flag(hub, f, sub->request_id, fill->descending, r);
  moqtrun_upf_budget(f, fill->has_timeout, fill->timeout_ms);
  moqtrun_upf_fill(hub, f, r);
  moqtrun_fetch_start(hub, f->up_state ? 0 : f);
}
