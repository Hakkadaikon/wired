#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_fetch_range_bad(
    const wired_moqtrun_track* t, moqctl_loc start, moqctl_loc end);
static void moqtrun_fetch_clamp(
    moqtrun_frange* r, const wired_moqtrun_track* t, moqctl_loc end);
static void moqtrun_fetch_held(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const moqfetch_req*        m,
    const wired_moqtrun_track* t,
    moqtrun_key                k);

void moqtrun_fetch_start(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (f) {
    moqtrun_fetch_serve(hub, f);
  }
}

/* 10.12.3 INVALID_RANGE: nothing published, Start past the Largest
 * Object, or End not past Start. */
static int moqtrun_fetch_range_bad(
    const wired_moqtrun_track* t, moqctl_loc start, moqctl_loc end) {
  return !t->has_largest || moqctl_loc_less(t->largest, start) ||
         !moqctl_loc_less(start, end);
}

/* 10.13: an End (inclusive) past the Largest Object is cut to the Largest
 * Object, and FETCH_OK says so. */
static void moqtrun_fetch_clamp(
    moqtrun_frange* r, const wired_moqtrun_track* t, moqctl_loc end) {
  moqctl_loc top = moqtrun_after(t->largest);
  r->end         = moqtrun_end_excl(end);
  r->ok_end      = end;
  if (!moqctl_loc_less(top, r->end)) {
    return;
  }
  r->end    = top;
  r->ok_end = t->largest;
}

/* rl resolved against t into r; 0 when the range is INVALID_RANGE
 * (10.12.3). */
int moqtrun_fetch_resolve(
    const wired_moqtrun_track* t,
    const moqctl_rangeloc*     rl,
    moqtrun_frange*            r) {
  moqctl_loc start, end;
  if (rl->sk == MOQCTL_RSK_NEXT_OBJ) {
    return 0; /* always past Largest */
  }
  start = MOQTRUN_START_FNS[rl->sk](moqtrun_track_top(t), rl);
  end   = moqfetch_req_end(rl, t->largest);
  if (moqtrun_fetch_range_bad(t, start, moqtrun_end_excl(end))) {
    return 0;
  }
  r->tag   = t->cache_tag;
  r->props = moqtrun_track_props(t);
  r->start = start;
  moqtrun_fetch_clamp(r, t, end);
  return 1;
}

/* A Standalone Fetch of t (k): what the cache lacks at the front of the
 * range is fetched upstream first (moqtrun_upf_go). */
static void moqtrun_fetch_held(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const moqfetch_req*        m,
    const wired_moqtrun_track* t,
    moqtrun_key                k) {
  moqtrun_frange r;
  if (!moqtrun_fetch_resolve(t, &m->range, &r)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INVALID_RANGE);
    return;
  }
  moqtrun_upf_go(
      hub,
      moqtrun_fetch_accept(
          hub, p, m->request_id, &r, moqtrun_fetch_order_desc(&m->params)),
      k, &r, &m->params);
}

/* A Standalone Fetch (draft-19 10.12.1; every draft-22 FETCH): of a
 * peer-published track, else of one a covering announcer may have. */
void moqtrun_fetch_standalone(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqfetch_req* m) {
  u8                   ns_buf[WIRED_MOQTRUN_MAX_NS];
  moqtrun_key          k = moqtrun_key_of(&m->track, ns_buf);
  wired_moqtrun_track* t = moqtrun_find_published_track(hub, k);
  if (!t) {
    moqtrun_upf_no_track(hub, p, m, k);
    return;
  }
  moqtrun_fetch_held(hub, p, m, t, k);
}

/* ============ fill fetch streams (draft-22 SS9.20.15) ============ */

/* Rewinds f to serve r by descending Group (Objects within a group stay
 * ascending, 11.4.4.1): its window becomes the top group's slice of r,
 * stepped down past groups with nothing to serve.
 * Gaps, read literally (d22 3.2.2): the first expected Object is
 * {End.Group, 0}, the last {Start.Group, 2^64-1}, and between items in
 * different groups the gap is the tail of the first one's group, every
 * skipped group, and the next group from Object 0 up to the item. An
 * unmarked gap means nonexistent, which is what a skipped group or
 * Object is here (moqcache_skip). A group the cache cannot vouch for is
 * one End of Unknown Range per group ending at {g, max} (the window end):
 * running from the previous item (11.4.1.2), it also covers that item's
 * group tail, nonexistent but reported unknown. Start.Group's Objects
 * below Start.Object fall in a gap too, outside the requested range. */
void moqtrun_fetch_descend(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqtrun_frange* r) {
  moqtrun_fwin w    = {r->start, r->end};
  u64          g    = moqtrun_fwin_group(&w);
  f->descending     = 1;
  f->seq.descending = 1;
  f->lo             = r->start;
  moqtrun_fetch_after(
      hub, f, g == r->start.group ? r->start : moqctl_loc_of(g, 0), &w);
  f->cursor = w.cursor;
  f->end    = w.end;
}

/* f marked as the fill of the subscription owner_rid, serving under its
 * own FETCH_HEADER Request ID: fills exist on draft-22 only, so 0x20C is
 * legal on the stream (SS11.4.1), and a Descending GROUP_ORDER rewinds
 * it to the range's top group. */
void moqtrun_fill_flag(
    wired_moqt_hub*       hub,
    wired_moqtrun_fetch*  f,
    u64                   owner_rid,
    int                   descending,
    const moqtrun_frange* r) {
  f->is_fill           = 1;
  f->owner_rid         = owner_rid;
  f->seq.eor_timed_out = 1;
  if (descending) {
    moqtrun_fetch_descend(hub, f, r);
  }
}
