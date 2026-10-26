#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_fill_of_tag(const wired_moqtrun_fetch* f, u64 tag);
static void moqtrun_fill_upstream_gone_one(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f);
static void moqtrun_fills_tag_gone(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, u64 tag);
static int moqtrun_fetch_under(const wired_moqtrun_fetch* f, u64 rid);
static int moqtrun_fetch_is_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid);
static void moqtrun_fetch_arr_cancel(
    wired_moqt_hub*         hub,
    wired_moqtrun_fetch*    arr,
    const wired_wt_session* s,
    u64                     rid);
static int moqtrun_fetch_on_stream(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid);
static int moqtrun_encode_fetch_ok(wired_mspan buf, usz* off, const void* m);
static int moqtrun_encode_fetch_ok19(wired_mspan buf, usz* off, const void* m);
static moqtrun_body_encode_fn moqtrun_fetch_ok_encoder(int ver);

/* 1 iff f is a live fill serving track incarnation tag. */
static int moqtrun_fill_of_tag(const wired_moqtrun_fetch* f, u64 tag) {
  return f->in_use && f->is_fill && f->cache_tag == tag;
}

/* The upstream publisher of tag left: a fill is a live continuation of
 * its subscription, so it cannot go on (unlike a FETCH of what remains
 * cached). Its upstream FETCH is let go at once; open fills reset
 * INTERNAL_ERROR now, and so does one that was waiting on an upstream
 * FETCH (opened just to signal the failure, 3.3.4); one the transport
 * refused a stream stays held until it gets one. */
static void moqtrun_fill_upstream_gone_one(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqtrun_upf_cancel(hub, f);
  f->failed = 1;
  if (f->opened || f->up_wt) {
    moqtrun_fetch_fail_due(hub, f);
  }
}

static void moqtrun_fills_tag_gone(
    wired_moqt_hub* hub, wired_moqtrun_fetch* arr, u64 tag) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_fill_of_tag(&arr[i], tag)) {
      moqtrun_fill_upstream_gone_one(hub, &arr[i]);
    }
  }
}

void moqtrun_fills_upstream_gone(wired_moqt_hub* hub, u64 tag) {
  moqtrun_fills_tag_gone(hub, hub->fetches, tag);
  moqtrun_fills_tag_gone(hub, hub->fetch_waits, tag);
}

/* 1 iff f is served by the tick pass of direction descending. */
int moqtrun_fetch_in_pass(const wired_moqtrun_fetch* f, int descending) {
  return moqtrun_fetch_live(f) && f->descending == descending;
}

/* One serving pass over the fetch table, descending fills only when
 * descending -- ascending backlog goes out before the live rounds of
 * the same tick, a descending one after them (SS9.20.15: catch-up
 * precedes live only while it serves the Objects right behind it).
 * Waiting fills move into freed slots first, so they serve this pass. */
void moqtrun_fetches_tick(wired_moqt_hub* hub, int descending) {
  moqtrun_fill_waits_tick(hub, descending);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_fetch_in_pass(&hub->fetches[i], descending)) {
      moqtrun_fetch_tick_one(hub, &hub->fetches[i]);
    }
  }
}

/* 1 iff f answers request rid, or is a fill owned by subscription rid
 * (a REQUEST_UPDATE's fill carries its own request_id but dies with the
 * subscription, SS9.20.15). */
static int moqtrun_fetch_under(const wired_moqtrun_fetch* f, u64 rid) {
  return f->request_id == rid || (f->is_fill && f->owner_rid == rid);
}

static int moqtrun_fetch_is_req(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid) {
  return moqtrun_fetch_owned(f, s) && moqtrun_fetch_under(f, rid);
}

static void moqtrun_fetch_arr_cancel(
    wired_moqt_hub*         hub,
    wired_moqtrun_fetch*    arr,
    const wired_wt_session* s,
    u64                     rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_fetch_is_req(&arr[i], s, rid)) {
      moqtrun_fetch_stop(hub, &arr[i]);
    }
  }
}

/* The FETCH request rid of s was cancelled (3.3.3): its fetch stops,
 * and a fill of rid still waiting for a serving slot is dropped without
 * ever opening (the cancel is a held fill's only other exit). */
void moqtrun_fetches_cancel(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 rid) {
  moqtrun_fetch_arr_cancel(hub, hub->fetches, s, rid);
  moqtrun_fetch_arr_cancel(hub, hub->fetch_waits, s, rid);
}

static int moqtrun_fetch_on_stream(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid) {
  return moqtrun_fetch_owned(f, s) && f->opened && f->stream_id == sid;
}

/* The peer stopped (or reset) s's fetch data stream sid: nothing more
 * can be sent on it, so its slot is freed. */
void moqtrun_fetches_stream_gone(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_fetch_on_stream(&hub->fetches[i], s, sid)) {
      moqtrun_fetch_free(hub, &hub->fetches[i]);
    }
  }
}

static int moqtrun_encode_fetch_ok(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_ok_encode(buf, off, m);
}

static int moqtrun_encode_fetch_ok19(wired_mspan buf, usz* off, const void* m) {
  return moqfetch_ok19_encode(buf, off, m);
}

/* End Location on the wire: inclusive in draft-22 (SS9.12), last + 1 with
 * Object 0 = whole group before (10.13). */
static moqtrun_body_encode_fn moqtrun_fetch_ok_encoder(int ver) {
  return (moqver_caps(ver) & MOQVER_CAP_FETCH_END_INCLUSIVE)
             ? moqtrun_encode_fetch_ok
             : moqtrun_encode_fetch_ok19;
}

/* FETCH_OK ok (End Location inclusive) in p's draft. */
void moqtrun_queue_fetch_ok_m(wired_moqtrun_peer* p, const moqfetch_ok* ok) {
  u8  msg[WIRED_MOQTRUN_CTL_MSG_MAX + WIRED_MOQTRUN_CTL_HDR_MAX];
  usz n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQFETCH_T_FETCH_OK,
      moqtrun_fetch_ok_encoder(p->ver), ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* FETCH_OK (10.13): not End Of Track, End Location end (inclusive), no
 * parameters; the track's Track Properties props (draft-18 9.6). */
void moqtrun_queue_fetch_ok(
    wired_moqtrun_peer* p, moqctl_loc end, wired_span props) {
  moqfetch_ok ok      = {0};
  ok.end              = end;
  ok.track_properties = props;
  moqtrun_queue_fetch_ok_m(p, &ok);
}
