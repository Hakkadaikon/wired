#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_pubdone_req_is(
    const wired_moqtrun_req* q, const wired_moqtrun_peer* p, u64 rid);
static void moqtrun_pubdone_req_end(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, u64 rid);
static int  moqtrun_fetch_of_tag(const wired_moqtrun_fetch* f, u64 tag);
static void moqtrun_fetches_tag_stop(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, u64 tag);
static void moqtrun_pubdone_req_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const wired_moqtrun_track* t);
static void moqtrun_pubdone_finish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
static int moqtrun_pubdone_peer(wired_moqt_hub* hub, wired_moqtrun_peer* p);

static int moqtrun_pubdone_req_is(
    const wired_moqtrun_req* q, const wired_moqtrun_peer* p, u64 rid) {
  return moqtrun_req_owned(q, p->wt) && q->kind == MOQCTL_T_PUBLISH &&
         q->request_id == rid;
}

/* p's PUBLISH rid is complete: the hub's side ends once flushed. */
static void moqtrun_pubdone_req_end(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_pubdone_req_is(&hub->reqs[i], p, rid)) hub->reqs[i].live = 0;
}

static int moqtrun_fetch_of_tag(const wired_moqtrun_fetch* f, u64 tag) {
  return f->in_use && f->cache_tag == tag;
}

static void moqtrun_fetches_tag_stop(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, u64 tag) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++)
    if (moqtrun_fetch_of_tag(&arr[i], tag))
      moqtrun_fetch_stop_code(hub, &arr[i], MOQTRUN_RESET_MALFORMED_TRACK);
}

/* A relay that detects a Malformed Track resets its fetch streams
 * MALFORMED_TRACK and, as the publisher's subscriber, cancels its request
 * (draft-22 12.1, 6.4.2.3: RESET_STREAM + STOP_SENDING). An upstream
 * SUBSCRIBE is cancelled once the track retires (moqtrun_up_end). */
void moqtrun_malformed_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  moqtrun_fetches_tag_stop(hub, hub->fetches, t->cache_tag);
  moqtrun_fetches_tag_stop(hub, hub->fetch_waits, t->cache_tag);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    wired_moqtrun_req* q = &hub->reqs[i];
    if (!moqtrun_pubdone_req_is(q, p, t->request_id)) continue;
    hub->io.stream_reset(p->wt, q->stream_id, MOQTRUN_RESET_CANCELLED);
    moqtrun_stream_stop(hub, p, q->stream_id, MOQTRUN_RESET_CANCELLED);
    q->live    = 0;
    q->fin_out = 1;
  }
}

/* The hub's side of the request behind t: ended once flushed, or
 * cancelled for a Malformed Track. */
static void moqtrun_pubdone_req_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  if (t->malformed) {
    moqtrun_malformed_cancel(hub, p, t);
    return;
  }
  moqtrun_pubdone_req_end(hub, p, t->request_id);
}

/* PUBLISH_DONE to every subscriber of p's track t (streams still open
 * reset first, moqtrun_sub_done), then t is retired. */
static void moqtrun_pubdone_finish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t) {
  moqtrun_track_ended(hub, t);
  moqtrun_pubdone_req_close(hub, p, t);
  t->pubdone_pending = 0;
  moqtrun_track_retire(hub, t);
}

/* 1 when t's waiting PUBLISH_DONE went out. */
int moqtrun_pubdone_try(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t) {
  if (!moqtrun_pubdone_ready(hub, t)) return 0;
  moqtrun_pubdone_finish(hub, p, t);
  return 1;
}

static int moqtrun_pubdone_peer(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  int n = 0;
  if (!p->in_use) return 0;
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    n += moqtrun_pubdone_try(hub, p, &p->tracks[t]);
  return n;
}

/* Sends every waiting PUBLISH_DONE now due; the request streams are
 * settled only when one went out. */
void moqtrun_pubdone_sweep(wired_moqt_hub* hub) {
  int n = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    n += moqtrun_pubdone_peer(hub, &hub->peers[i]);
  n += moqtsw_step(hub, moqtrun_sw_ops()); /* SWITCH_FROM (moqtswitch.c) */
  if (n) moqtrun_reqs_tick(hub);
}

/* p's PUBLISH rid is cancelled: a PUBLISH_DONE still waiting goes out
 * now. */
void moqtrun_pubdone_flush(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid) {
  wired_moqtrun_track* t = moqtrun_pubdone_track_of(p, rid);
  if (t && t->pubdone_pending) moqtrun_pubdone_finish(hub, p, t);
}
