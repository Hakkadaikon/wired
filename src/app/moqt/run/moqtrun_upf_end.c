#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_end_behind(const wired_moqtrun_fetch* f, moqctl_loc e);
static moqctl_loc moqtrun_upf_end_for(
    const wired_moqtrun_peer* dp, moqctl_loc e);
static void moqtrun_upf_answer_ok(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqfetch_ok* up);
static int moqtrun_upf_complete(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
static void moqtrun_upf_ok_checked(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_ok*   ok,
    moqctl_loc           e);
static void moqtrun_upf_ok(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    const moqfetch_ok*   ok);

/* An End below an item already relayed cannot be. */
static int moqtrun_upf_end_behind(const wired_moqtrun_fetch* f, moqctl_loc e) {
  return f->has_up_last && moqctl_loc_less(e, f->up_last);
}

/* draft-22 has no "whole group" End Location. */
static moqctl_loc moqtrun_upf_end_for(
    const wired_moqtrun_peer* dp, moqctl_loc e) {
  int whole = e.object == MOQFETCH_OBJ_GROUP_END;
  return whole && (moqver_caps(dp->ver) & MOQVER_CAP_FETCH_END_INCLUSIVE)
             ? moqctl_loc_of(e.group, MOQCACHE_OBJ_ID_MAX)
             : e;
}

/* A FETCH of a track the hub does not hold is answered with the upstream
 * End Location, End Of Track and Track Properties (7.6), and its range
 * ends there. */
static void moqtrun_upf_answer_ok(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqfetch_ok* up) {
  moqfetch_ok         ok = {0};
  wired_moqtrun_peer* dp = moqtrun_find_by_wt(hub, f->wt);
  if (!moqtrun_upf_unanswered(f) || !dp) return;
  ok.end              = moqtrun_upf_end_for(dp, f->up_end);
  ok.end_of_track     = up->end_of_track;
  ok.track_properties = up->track_properties;
  f->end              = moqtrun_end_excl(f->up_end);
  moqtrun_upf_answer(hub, f, moqtrun_upf_say_ok, &ok);
}

/* The FETCH_OK and the data stream's FIN are in, and nothing of it is
 * kept back for a retry. */
static int moqtrun_upf_complete(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  return f->up_state == WIRED_MOQTRUN_UPF_OK && f->up_data_end &&
         hub->upf_owner != f;
}

/* The request is complete: the cache side takes the rest. */
void moqtrun_upf_done_if(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (!moqtrun_upf_complete(hub, f)) return;
  moqtrun_upf_drop(hub, f, MOQTRUN_UPF_IO_FIN);
  moqtrun_upf_resume(hub, f, 1, 1);
}

static void moqtrun_upf_ok_checked(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_ok*   ok,
    moqctl_loc           e) {
  if (moqtrun_upf_mandatory(ok->track_properties)) {
    moqtrun_upf_mand(hub, f);
    return;
  }
  if (moqtrun_upf_end_behind(f, e)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  f->up_state = WIRED_MOQTRUN_UPF_OK;
  f->up_end   = e;
  f->up_eot   = ok->end_of_track != 0;
  moqtrun_upf_answer_ok(hub, f, ok);
  moqtrun_upf_done_if(hub, f);
}

/* FETCH_OK (9.12): an End before the Start closes the session
 * PROTOCOL_VIOLATION; a second FETCH_OK is ignored. */
static void moqtrun_upf_ok(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    const moqfetch_ok*   ok) {
  moqctl_loc e = moqtrun_upf_ok_end(pp, ok);
  if (f->up_state != WIRED_MOQTRUN_UPF_SENT) return;
  if (moqctl_loc_less(e, f->up_lo)) {
    moqtrun_close_with(hub, pp, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_NONE, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_upf_ok_checked(hub, f, ok, e);
}

/* A reply that does not decode closes the upstream session (and so ends
 * the leg). */
void moqtrun_upf_on_ok(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           body) {
  moqfetch_ok ok;
  if (!moqtrun_take_or_close(hub, pp, moqfetch_ok_take(pp->ver, body, &ok))) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_NONE, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_upf_ok(hub, pp, f, &ok);
}
