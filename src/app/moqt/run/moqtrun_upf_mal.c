#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_mal_at(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    const moqfetch_obj*        o,
    wired_span                 pre);
static int moqtrun_upf_malformed(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    const moqfetch_obj*        o,
    wired_span                 pre);
static void moqtrun_upf_mal_stop(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
static int  moqtrun_upf_other_leg(
    const wired_moqtrun_fetch* g, const wired_moqtrun_fetch* f);
static int moqtrun_upf_same_name(
    const wired_moqtrun_upf_leg* g, const wired_moqtrun_upf_leg* f);
static int moqtrun_upf_same_track(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* g,
    const wired_moqtrun_fetch* f);
static void moqtrun_upf_mal_peers(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
static int moqtrun_peer_owns(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t);
static void moqtrun_upf_mal(wired_moqt_hub* hub, wired_moqtrun_fetch* f);

/* #4/#5 against what the held track saw, #5 against the upstream
 * FETCH_OK, #6 against the cache (pre: the payload's first bytes). */
static int moqtrun_upf_mal_at(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    const moqfetch_obj*        o,
    wired_span                 pre) {
  moqctl_loc l = moqtrun_upf_loc(o);
  return moqtrun_upf_past_end(f, l) ||
         moqtrun_obj_malformed(moqtrun_upf_track(hub, f), l) ||
         moqtrun_upf_conflicts(hub, f, l, o->payload.n, 0, pre);
}

static int moqtrun_upf_malformed(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* f,
    const moqfetch_obj*        o,
    wired_span                 pre) {
  return o->flags < 0x80 && moqtrun_upf_mal_at(hub, f, o, pre);
}

/* f reset MALFORMED_TRACK, opened first if need be so its requester
 * learns why -- unless that open sent the range whole and freed f. */
static void moqtrun_upf_mal_stop(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqtrun_fetch_open(hub, f);
  if (f->in_use) {
    moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_MALFORMED_TRACK);
  }
}

static int moqtrun_upf_other_leg(
    const wired_moqtrun_fetch* g, const wired_moqtrun_fetch* f) {
  return g != f && moqtrun_upf_live(g);
}

static int moqtrun_upf_same_name(
    const wired_moqtrun_upf_leg* g, const wired_moqtrun_upf_leg* f) {
  return moqtrun_ns_eq(g->ns, g->ns_len, wired_span_of(f->ns, f->ns_len)) &&
         moqtrun_ns_eq(
             g->name, g->name_len, wired_span_of(f->name, f->name_len));
}

/* g fetches f's track from f's publisher too. */
static int moqtrun_upf_same_track(
    wired_moqt_hub*            hub,
    const wired_moqtrun_fetch* g,
    const wired_moqtrun_fetch* f) {
  return moqtrun_upf_other_leg(g, f) && g->up_wt == f->up_wt &&
         moqtrun_upf_same_name(
             moqtrun_upf_leg_of(hub, g), moqtrun_upf_leg_of(hub, f));
}

static void moqtrun_upf_mal_peers(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_same_track(hub, &hub->fetches[i], f)) {
      moqtrun_upf_mal_stop(hub, &hub->fetches[i]);
    }
  }
}

/* t is one of p's own tracks. Compared as addresses: t may be 0 or in
 * another array, where pointer ordering is undefined. */
static int moqtrun_peer_owns(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  return p && (usz)t - (usz)p->tracks < sizeof p->tracks;
}

/* A malformed upstream Object is neither relayed nor cached; the fetch is
 * reset MALFORMED_TRACK and so is every other fetch of the track from
 * that publisher -- a held track's, when that publisher owns it, through
 * its PUBLISH_DONE MALFORMED_TRACK (moqtrun_pubdone_sweep,
 * moqtrun_malformed_cancel). Another announcer cannot end the owner's
 * track: only its own legs stop. */
static void moqtrun_upf_mal(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  wired_moqtrun_track* t = moqtrun_upf_track(hub, f);
  if (moqtrun_peer_owns(moqtrun_find_by_wt(hub, f->up_wt), t)) {
    t->malformed = 1;
  } else {
    moqtrun_upf_mal_peers(hub, f);
  }
  moqtrun_upf_mal_stop(hub, f);
}

/* One upstream item: Malformed first; else relayed in place, or the leg
 * ends (never buffered or reordered, 7.8). */
void moqtrun_upf_item(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    const moqfetch_obj*  o,
    wired_span           pre) {
  if (moqtrun_upf_malformed(hub, f, o, pre)) {
    moqtrun_upf_mal(hub, f);
    return;
  }
  if (!moqtrun_upf_relay(hub, f, o, pre)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
  }
}

/* The next bytes c of the Object being passed through: Malformed when
 * they differ from the cached copy (12.1), else written out as they are.
 * 1 when written; a refusal leaves them to retry (moqtrun_upf_retry). */
int moqtrun_upf_chunk(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span c) {
  if (moqtrun_upf_conflicts(
          hub, f, f->up_last, f->up_pl_at + f->up_pl_left, f->up_pl_at, c)) {
    moqtrun_upf_mal(hub, f);
    return 0;
  }
  if (hub->io.stream_send(f->wt, f->stream_id, c, 0) <= 0) {
    return 0;
  }
  f->up_pl_at += c.n;
  f->up_pl_left -= c.n;
  f->last_ok_ms = hub->live.last_now_ms;
  return 1;
}
