#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_gap(
    moqcache* c, const moqtrun_frange* r, moqcache_item* last);
static void moqtrun_upf_span(
    wired_moqtrun_fetch*  f,
    const moqtrun_frange* r,
    const moqcache_item*  gap,
    moqctl_rangeloc*      rl);
static int moqtrun_upf_try(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    moqtrun_key           k,
    const moqtrun_frange* r,
    const moqctl_params*  params);
static void moqtrun_upf_stop_data(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f);

/* The last item of r the cache cannot vouch for, in *last; 0 when it
 * vouches for all of r. ponytail: one cache walk per fetch, like
 * moqtrun_fetch_last. */
static int moqtrun_upf_gap(
    moqcache* c, const moqtrun_frange* r, moqcache_item* last) {
  moqcache_item it;
  int           found = 0;
  for (moqctl_loc cur = moqcache_skip(c, r->tag, r->start, r->end);
       moqctl_loc_less(cur, r->end);
       cur = moqcache_skip(c, r->tag, it.next, r->end)) {
    moqcache_item_at(c, r->tag, cur, r->end, &it);
    if (it.unknown) {
      *last = it;
      found = 1;
    }
  }
  return found;
}

/* The span: [range start, just past the last gap); Descending, all of r
 * (the cache walks the other way). rl asks for exactly that. */
static void moqtrun_upf_span(
    wired_moqtrun_fetch*  f,
    const moqtrun_frange* r,
    const moqcache_item*  gap,
    moqctl_rangeloc*      rl) {
  f->up_lo         = r->start;
  f->up_span_end   = f->descending ? r->end : gap->next;
  *rl              = (moqctl_rangeloc){0};
  rl->sk           = MOQCTL_RSK_ABS;
  rl->start_group  = r->start.group;
  rl->start_object = r->start.object;
  moqtrun_upf_rl_end(rl, moqctl_loc_prev(f->up_span_end));
}

/* 1 when f's leg starts for r of track k: the cache lacks part of it,
 * FILL_TIMEOUT is not 0, and a publisher can be asked. */
static int moqtrun_upf_try(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    moqtrun_key           k,
    const moqtrun_frange* r,
    const moqctl_params*  params) {
  moqcache_item   gap;
  moqctl_rangeloc rl;
  if (f->up_tmo || !moqtrun_upf_gap(&hub->cache, r, &gap)) return 0;
  moqtrun_upf_span(f, r, &gap, &rl);
  return moqtrun_upf_open(
      hub, f, moqtrun_upf_target(hub, moqtrun_upf_owner(hub, k), f->wt, k), k,
      &rl, params);
}

/* An accepted FETCH f (0: refused) of k over r: its upstream FETCH goes
 * out first when the cache lacks part of r, else it serves from the
 * cache at once. */
void moqtrun_upf_go(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    moqtrun_key           k,
    const moqtrun_frange* r,
    const moqctl_params*  params) {
  if (!f) return;
  moqtrun_upf_budget_of(f, params);
  if (!moqtrun_upf_try(hub, f, k, r, params)) moqtrun_fetch_serve(hub, f);
}

/* A fill f over r: its upstream FETCH goes out when the cache lacks part
 * of r (the caller serves it otherwise). */
void moqtrun_upf_fill(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r) {
  wired_moqtrun_track* t = moqtrun_pubst_track(hub, f->cache_tag);
  if (t)
    moqtrun_upf_try(hub, f, moqtrun_track_key(t), r, &MOQTRUN_UPF_NO_PARAMS);
}

/* ----- ending the leg ----- */

/* STOP_SENDING on the upstream data stream while it still sends. */
static void moqtrun_upf_stop_data(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f) {
  if (f->up_data_open && !f->up_data_end)
    moqtrun_stream_stop(hub, pp, f->up_data_sid, MOQTRUN_RESET_CANCELLED);
}

void moqtrun_upf_io_none(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f) {
  (void)hub;
  (void)pp;
  (void)f;
}

/* draft-22 3.2.4 / 6.4.2.3: cancelled -- RESET_STREAM and STOP_SENDING
 * (CANCELLED) on the request stream, STOP_SENDING on the data stream. */
void moqtrun_upf_io_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f) {
  hub->io.stream_reset(f->up_wt, f->up_req_sid, MOQTRUN_RESET_CANCELLED);
  moqtrun_stream_stop(hub, pp, f->up_req_sid, MOQTRUN_RESET_CANCELLED);
  moqtrun_upf_stop_data(hub, pp, f);
}

/* The request is complete: the hub FINs its side (3.3.2). */
void moqtrun_upf_io_fin(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f) {
  hub->io.stream_fin(f->up_wt, f->up_req_sid);
  moqtrun_upf_stop_data(hub, pp, f);
}
