#include "app/moqt/run/moqtrun_impl.h"

static moqctl_loc moqtrun_upf_covered(const wired_moqtrun_fetch* f);
static void       moqtrun_upf_from_asc(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int done);
static void moqtrun_upf_window(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
static void moqtrun_upf_from_desc(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int done);
static int moqtrun_upf_nt_desc_failed(const wired_moqtrun_fetch* f, int done);

static const moqtrun_upf_io_fn MOQTRUN_UPF_IO[] = {
    moqtrun_upf_io_none, moqtrun_upf_io_cancel, moqtrun_upf_io_fin};

/* f's held torn Object head (if any) is let go. */
void moqtrun_upf_unhold(wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  if (hub->upf_owner != f) return;
  hub->upf_owner = 0;
  hub->upf_len   = 0;
}

/* Ends f's leg with io (MOQTRUN_UPF_IO_*) -- none toward a session gone
 * or being closed. A data stream bound to f stays bound, its later bytes
 * discarded. */
void moqtrun_upf_drop(wired_moqt_hub* hub, wired_moqtrun_fetch* f, int io) {
  wired_moqtrun_peer* pp = moqtrun_find_by_wt(hub, f->up_wt);
  if (moqtrun_rdv_peer_open(pp)) MOQTRUN_UPF_IO[io](hub, pp, f);
  f->up_state = WIRED_MOQTRUN_UPF_NONE;
  moqtrun_upf_unhold(hub, f);
}

int moqtrun_upf_live(const wired_moqtrun_fetch* f) {
  return f->up_state != WIRED_MOQTRUN_UPF_NONE;
}

/* f's leg runs toward session s. */
int moqtrun_upf_leg_to(
    const wired_moqtrun_fetch* f, const wired_wt_session* s) {
  return moqtrun_upf_live(f) && f->up_wt == s;
}

/* Cancels f's leg if it still runs. */
void moqtrun_upf_cancel(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (moqtrun_upf_live(f)) moqtrun_upf_drop(hub, f, MOQTRUN_UPF_IO_CANCEL);
}

/* ----- the cache side takes over ----- */

/* Just past what a completed leg covered: its End, within the span. */
static moqctl_loc moqtrun_upf_covered(const wired_moqtrun_fetch* f) {
  moqctl_loc e = moqtrun_end_excl(f->up_end);
  return moqctl_loc_min(e, f->up_span_end);
}

/* Ascending: from just past the last relayed item (or the cursor), and
 * after a completed leg not before what it covered. */
static void moqtrun_upf_from_asc(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int done) {
  moqctl_loc from = f->has_up_last ? moqtrun_after(f->up_last) : f->cursor;
  if (done) from = moqctl_loc_max(from, moqtrun_upf_covered(f));
  f->cursor = moqcache_skip(&hub->cache, f->cache_tag, from, f->end);
}

/* Descending: the window of the last relayed item's group, past it. */
static void moqtrun_upf_window(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqctl_loc   top = moqctl_loc_of(f->up_last.group + 1, 0);
  moqtrun_fwin w;
  f->end = moqctl_loc_min(top, f->up_span_end);
  moqtrun_fetch_after(hub, f, moqtrun_after(f->up_last), &w);
  f->cursor = w.cursor;
  f->end    = w.end;
}

/* Descending: a completed leg covered the whole range; a failed one hands
 * over past its last relayed item (or, with none, from the top). */
static void moqtrun_upf_from_desc(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int done) {
  if (done) {
    f->cursor = f->end;
    return;
  }
  if (f->has_up_last) moqtrun_upf_window(hub, f);
}

static const moqtrun_upf_from_fn MOQTRUN_UPF_FROM[] = {
    moqtrun_upf_from_asc, moqtrun_upf_from_desc};

/* A Descending FETCH of a track the hub does not hold has no cache side
 * to hand a failed leg to (what lies below the cursor is unknown to the
 * hub, start and all), and no fetch can go on in the middle of an Object
 * the leg was passing through: either is reset instead (3.2.2). */
static int moqtrun_upf_nt_desc_failed(const wired_moqtrun_fetch* f, int done) {
  return f->no_track && f->descending && !done;
}

int moqtrun_upf_no_window(const wired_moqtrun_fetch* f, int done) {
  return f->up_pl_left || moqtrun_upf_nt_desc_failed(f, done);
}

/* The cache side takes over (3.2.3), stall-checked from now: after a
 * completed leg (done) from just past what it covered, after a failed one
 * at the cursor; served now when serve, else from the next tick. */
void moqtrun_upf_resume(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int done, int serve) {
  if (moqtrun_upf_no_window(f, done)) {
    moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_INTERNAL_ERROR);
    return;
  }
  MOQTRUN_UPF_FROM[f->descending != 0](hub, f, done);
  f->last_ok_ms = hub->live.last_now_ms;
  if (serve) moqtrun_fetch_serve(hub, f);
}

/* ----- answering a FETCH of a track the hub does not hold ----- */

int moqtrun_upf_unanswered(const wired_moqtrun_fetch* f) {
  return f->no_track && !f->answered;
}

/* f's downstream request stream (*dp its session), else 0. */
wired_moqtrun_req* moqtrun_upf_req(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    wired_moqtrun_peer**       dp) {
  *dp = moqtrun_find_by_wt(hub, f->wt);
  return moqtrun_rdv_peer_open(*dp) ? moqtrun_req_find(hub, f->wt, f->req_sid)
                                    : 0;
}

void moqtrun_upf_say_ok(wired_moqtrun_peer* dp, const void* msg) {
  moqtrun_queue_fetch_ok_m(dp, msg);
}
