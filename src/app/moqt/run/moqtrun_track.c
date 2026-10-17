#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_relay_orphan_ok(
    const wired_moqtrun_track* t, const wired_moqtrun_relay* r, usz si);
static int moqtrun_loc_newer(const wired_moqtrun_track* t, moqctl_loc l);

/* Clears t's subscriber slots -- only needed the first time a fresh (not
 * re-PUBLISHed) slot is claimed. */
void moqtrun_track_clear_subs(wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) t->subs[i].active = 0;
}

/* Also forgets each subscription's newest Group: a re-PUBLISH restarts
 * Group numbering. */
void moqtrun_track_clear_relays(wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) t->relays[r].in_use = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) t->subs[i].newest_sid = 0;
}

/* 1 iff relay r's subscriber slot si names a stream AND that slot's
 * subscription is still Established -- the two preconditions
 * moqtrun_relay_reset_one_sub needs before it may touch hub->peers[] (an
 * inactive slot's session_idx is garbage, not a safe index: freestanding
 * memory starts unzeroed, the same reason every other sub->session_idx use
 * in this file is guarded on ->active first, e.g. moqtrun_relay_object). */
static int moqtrun_relay_orphan_ok(
    const wired_moqtrun_track* t, const wired_moqtrun_relay* r, usz si) {
  return r->sub_stream_set[si] && t->subs[si].active;
}

/* Resets subscriber slot si's still-open relay stream on relay r, if it has
 * one: the WT layer, not just this hub's own bookkeeping, must be told the
 * stream is dead, or the subscriber's peer-granted uni-stream credit for it
 * is never released (moqtrun_track_reset_stale_relays' own doc). */
void moqtrun_relay_reset_one_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_moqtrun_relay* r,
    usz                  si,
    u32                  code) {
  if (!moqtrun_relay_orphan_ok(t, r, si)) return;
  wired_moqtrun_peer* dst = &hub->peers[t->subs[si].session_idx];
  if (dst->in_use) hub->io.stream_reset(dst->wt, r->sub_stream_id[si], code);
  r->sub_stream_set[si] = 0;
}

void moqtrun_relay_reset_stale(
    wired_moqt_hub* hub, wired_moqtrun_track* t, wired_moqtrun_relay* r) {
  if (!r->in_use) return;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    moqtrun_relay_reset_one_sub(hub, t, r, si, MOQTRUN_RESET_INTERNAL_ERROR);
}

/* A publisher that drops mid-share (crash, network loss -- no clean FIN)
 * leaves every subscriber's relay stream open on the transport even though
 * this hub's own bookkeeping forgot it on session_close
 * (moqtrun_relays_clear_sub only clears sub_stream_set, never the
 * underlying stream). Left alone, every drop+reshare cycle permanently
 * burns one uni-stream credit slot on every subscriber (RFC 9000 4.6):
 * stream ids never get reused, and nothing else ever resets one of these
 * orphans, until the subscriber's whole connection eventually has no
 * credit left for ANY new stream, chat included -- observed live as
 * screen shares and chat both going silent for someone who never touched
 * their own browser. Called BEFORE moqtrun_track_clear_relays wipes the
 * bookkeeping this walk needs. */
void moqtrun_track_reset_stale_relays(
    wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    moqtrun_relay_reset_stale(hub, t, &t->relays[r]);
}

/* Returns relay r's bound ring to the pool on a publisher-side teardown
 * (the publisher's session closed, or a re-PUBLISH abandoned its old
 * streams). Nothing else can return it: the tick skips a dead
 * publisher's relays, so a ring left bound here would stay in_use
 * forever and each mid-stream disconnect would drain the pool by one
 * until every reliable stream fell back to lossy. Deliberately io-free:
 * on a session close the publisher's connection -- and any receive-
 * credit hold on it -- dies with the session, and on a re-PUBLISH a
 * still-held old stream stays harmlessly frozen: the hold is per-stream
 * (wired_server_wt_stream_hold), the publisher abandoned that stream (a
 * new PUBLISH opens new ones), and a receive slot resets its hold flag
 * when claimed, so the freeze can never leak onto a new stream. */
void moqtrun_rel_drop_ring(wired_moqt_hub* hub, wired_moqtrun_relay* r) {
  if (!r->in_use || r->rel_idx < 0) return;
  hub->rel_pool[r->rel_idx].in_use = 0;
  r->rel_idx                       = -1;
}

void moqtrun_track_drop_rings(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    moqtrun_rel_drop_ring(hub, &t->relays[r]);
}

void moqtrun_peer_drop_rings(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++)
    moqtrun_track_drop_rings(hub, &p->tracks[t]);
}

/* Claims slot t for a PUBLISH naming name/track_alias: clears subs only on
 * a fresh (not-yet-in_use) slot, so a re-PUBLISH under the same name keeps
 * its existing subscribers (matching the prior single-track hub's
 * overwrite behavior). Relays always clear: a (re-)PUBLISH means the
 * publisher's old streams are gone (and freestanding memory starts
 * unzeroed, so a fresh slot's relays hold garbage until this) -- but any
 * of those old streams still open on a subscriber's transport are reset
 * first, not just forgotten (moqtrun_track_reset_stale_relays' own doc). */
/* ===== Largest Object (draft 10.2.16) ===== */

static int moqtrun_loc_newer(const wired_moqtrun_track* t, moqctl_loc l) {
  return !t->has_largest || moqctl_loc_less(t->largest, l);
}

/* Notes an Object at {group, object} published on t (0: no track). */
void moqtrun_track_note(wired_moqtrun_track* t, u64 group, u64 object) {
  moqctl_loc l = {group, object};
  if (t && moqtrun_loc_newer(t, l)) {
    t->largest     = l;
    t->has_largest = 1;
  }
}

/* A relay MUST count the upstream PUBLISH's LARGEST_OBJECT (10.2.16). */
void moqtrun_track_seed_largest(
    wired_moqtrun_track* t, const moqctl_params* params) {
  const moqctl_param* l =
      moqctl_params_find(params, MOQCTL_PARAM_LARGEST_OBJECT);
  if (l) moqtrun_track_note(t, l->loc.group, l->loc.object);
}

/* A live track's incarnation ends: its cached Objects go and its fills
 * reset INTERNAL_ERROR (a slot never claimed holds no tag worth trusting). */
void moqtrun_track_cache_drop(
    wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  if (!t->in_use) return;
  moqtrun_fills_upstream_gone(hub, t->cache_tag);
  moqcache_release(&hub->cache, t->cache_tag);
}
