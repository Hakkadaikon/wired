#include "app/moqt/run/moqtrun_impl.h"

static i64 moqtrun_fetch_open_io(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, wired_span hdr);
static u8 moqtrun_fetch_sub_prio(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, usz idx);
static void moqtrun_fetch_opened(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, i64 sid);

/* ===================== FETCH (draft 10.12, 10.13, 11.4.4) =============== */

/* The Location right after l. */
moqctl_loc moqtrun_after(moqctl_loc l) {
  return moqctl_loc_of(l.group, l.object + 1);
}

/* An inclusive end (moqfetch_req_end; Object MOQFETCH_OBJ_GROUP_END = the
 * whole group) as an exclusive bound: the draft-19 End Location "last
 * Object + 1", whose Object 0 means the whole group (10.12.1). */
moqctl_loc moqtrun_end_excl(moqctl_loc incl) {
  moqctl_loc e = moqfetch_end19_wire(incl);
  return e.object ? e : moqctl_loc_of(e.group + 1, 0);
}

int moqtrun_fetch_live(const wired_moqtrun_fetch* f) { return f->in_use; }

wired_moqtrun_fetch* moqtrun_fetch_arr_slot(wired_moqtrun_fetch* arr) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (!moqtrun_fetch_live(&arr[i])) {
      return &arr[i];
    }
  }
  return 0;
}

wired_moqtrun_fetch* moqtrun_fetch_slot(wired_moqt_hub* hub) {
  return moqtrun_fetch_arr_slot(hub->fetches);
}

int moqtrun_fetch_done(const wired_moqtrun_fetch* f) {
  return !moqctl_loc_less(f->cursor, f->end);
}

/* The FETCH_HEADER stream (11.4.4); a range with nothing to serve is the
 * header alone, closed at once (10.12.3). */
static i64 moqtrun_fetch_open_io(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, wired_span hdr) {
  return moqtrun_fetch_done(f) ? hub->io.send_uni(f->wt, hdr)
                               : hub->io.open_uni_stream(f->wt, hdr);
}

/* f's Subscriber Priority: a fill's subscription's, else the default.
 * ponytail: a FETCH's own SUBSCRIBER_PRIORITY is not kept; store it on
 * the fetch slot if FETCHes need ranking against each other. */
static u8 moqtrun_fetch_sub_prio(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f, usz idx) {
  wired_moqtrun_track* t;
  wired_moqtrun_sub*   s =
      f->is_fill ? moqtrun_hub_sub_by_rid(hub, idx, f->owner_rid, &t) : 0;
  return s ? moqtrun_sub_prio(s) : 128;
}

/* f's open stream class: a fill in its subscription's flow, a FETCH in
 * its own, at the cursor's group, ahead of live streams of that group
 * (tie 0); Publisher Priority the 128 its Objects carry
 * (moqtrun_fetch_obj_of). */
void moqtrun_fetch_sched(wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  wired_moqtrun_peer* p = moqtrun_find_by_wt(hub, f->wt);
  if (!p) {
    return;
  }
  usz            idx = (usz)(p - hub->peers);
  u64            rid = f->is_fill ? f->owner_rid : f->request_id;
  wired_wt_sched k   = moqtrun_sched_of(
      moqtrun_fetch_sub_prio(hub, f, idx), 128, moqtrun_flow_of(idx, rid),
      moqtrun_group_rank(f->descending, f->cursor.group), 0);
  moqtrun_sched_apply(hub, f->wt, (i64)f->stream_id, &k);
}

/* The one place a fetch slot frees: an upstream FETCH still in flight
 * for it is cancelled first (draft-22 3.2.4), so none outlives it, and a
 * FETCH still unanswered is refused, so none is left without a reply. */
void moqtrun_fetch_free(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (f->up_state != WIRED_MOQTRUN_UPF_NONE) {
    moqtrun_upf_drop(hub, f, MOQTRUN_UPF_IO_CANCEL);
  }
  moqtrun_upf_unanswered_refuse(hub, f);
  f->in_use = 0;
}

/* f's stream sid just opened; an empty range was sent whole (header +
 * FIN) and is over. */
static void moqtrun_fetch_opened(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, i64 sid) {
  f->stream_id = (u64)sid;
  f->opened    = 1;
  moqtrun_fetch_sched(hub, f);
  f->last_ok_ms = hub->live.last_now_ms;
  if (moqtrun_fetch_done(f)) {
    moqtrun_fetch_free(hub, f);
  }
  moqtrun_fill_opened(hub, f);
}

/* 1 once f's stream is open; a refused open retries on the next tick.
 * 0 too when an empty range was sent whole and f freed: nothing more
 * goes on that stream. */
int moqtrun_fetch_open(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  u8  hdr[16]; /* Type 0x5 + a Request ID varint */
  usz n = 0;
  if (f->opened) {
    return 1;
  }
  moqfetch_hdr_put(wired_mspan_of(hdr, sizeof hdr), &n, f->request_id);
  i64 sid = moqtrun_fetch_open_io(hub, f, wired_span_of(hdr, n));
  if (sid < 0) {
    return 0;
  }
  moqtrun_fetch_opened(hub, f, sid);
  return f->in_use;
}
