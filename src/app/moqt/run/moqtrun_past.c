#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_cacheable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 status);
static int moqtrun_group_closed(const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_gone_on(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_cache_says_gone(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_gone_known(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_track_in(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t);
static int moqtrun_track_ver(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);

/* Decodes the SUBGROUP_HEADER + the one Object this subset always sends
 * whole in one call (1 message = 1 Object = 1 Group = 1
 * Subgroup). Returns 1 and fills *hdr on a fully decoded Object, 0
 * otherwise (nothing to relay -- covers INSUFFICIENT/VIOLATION alike, since
 * a hub-internal relay has no peer to report a VIOLATION to at this call
 * site). */
/* Decodes every complete Object following an already-decoded
 * SUBGROUP_HEADER (hdr, *off already past it), advancing *off past each one
 * in turn. Stops at the first Object that does not fully decode (buffer
 * ran out mid-Object, or a VIOLATION-shaped Object) -- *off is left at the
 * end of the last successfully decoded Object, never mid-Object
 * (moqdata_obj_take leaves *off unchanged on any non-OK result).
 * Returns the count of Objects decoded (0 if the very first one fails --
 * nothing to relay). A single-Object stream decodes identically to this
 * hub's former one-shot-Object path, this is that path's generalization to
 * N Objects on one stream. */
/* hub (0: not a peer track) caches each whole Object of t for FETCH
 * (draft 10.12.3). A Status-only Object has no payload a fetch Object
 * could carry (11.4.4), so it reads as nonexistent there. */
static int moqtrun_cacheable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 status) {
  return hub && t && status == MOQDATA_STATUS_NORMAL;
}

/* draft-18 12.3: the cached Object expires dur ms after it arrived (~0:
 * no MAX_CACHE_DURATION). shortcut: "arrived" is the last tick's clock,
 * not the Object's first byte -- never later, so it only expires early. */
static u64 moqtrun_cache_exp(u64 now, u64 dur) {
  return dur > ~(u64)0 - now ? ~(u64)0 : now + dur;
}

/* ----- Objects recorded as nonexistent (draft-18/19 9.1) ----- */

/* t moved past l's Group: the cache treats the Group as complete. */
static int moqtrun_group_closed(const wired_moqtrun_track* t, moqctl_loc l) {
  return t->has_largest && l.group < t->largest.group;
}

/* The cache reports l nonexistent: its skip moves past l (the rest of a
 * cached Group). */
static int moqtrun_cache_says_gone(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return moqctl_loc_less(
      l, moqcache_skip(&hub->cache, t->cache_tag, l, moqtrun_after(l)));
}

/* draft-18/19 9.1: "an endpoint can receive an Object after it has
 * already recorded that the Object does not exist. A caching relay
 * SHOULD NOT cache or forward the Object in this case." The hub's record
 * is its cache: a closed Group's Location the cache would serve (a FETCH)
 * as nonexistent. hub 0 (a scan of the hub's own bytes): never. */
static int moqtrun_gone_on(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return moqtrun_group_closed(t, l) && moqtrun_cache_says_gone(hub, t, l);
}

static int moqtrun_gone_known(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return hub && t && moqtrun_gone_on(hub, t, l);
}

static int moqtrun_track_in(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  return (usz)t - (usz)p->tracks < sizeof p->tracks;
}

/* The session publishing t, else 0. */
const wired_moqtrun_peer* moqtrun_track_peer(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_track_in(&hub->peers[i], t)) {
      return &hub->peers[i];
    }
  }
  return 0;
}

/* The draft of the session publishing t, -1 when none does. */
static int moqtrun_track_ver(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  const wired_moqtrun_peer* p = moqtrun_track_peer(hub, t);
  return p ? p->ver : -1;
}

/* Gates datagrams and Subgroup-stream Objects (moqtrun_gone.c). In
 * draft-23 the hub's inference is no record of non-existence: the
 * Object is Unknown there, and forwarded (2.1.2, 7.1). */
int moqtrun_obj_gone(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return moqtrun_gone_known(hub, t, l) &&
         !(moqver_caps(moqtrun_track_ver(hub, t)) & MOQVER_CAP_LATE_FORWARD);
}

/* t, or 0 when the Object at l is recorded nonexistent (not forwarded). */
wired_moqtrun_track* moqtrun_gone_gate(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqctl_loc l) {
  return moqtrun_obj_gone(hub, t, l) ? 0 : t;
}

void moqtrun_cache_obj(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    u64                  group,
    const moqdata_obj*   o) {
  /* Cached in arrival order, so an Object behind a later Group stays out
   * (moqcache.h: groups ascend per track). */
  if (!moqtrun_cacheable(hub, t, o->status) ||
      moqtrun_group_closed(t, moqctl_loc_of(group, o->object_id))) {
    return;
  }
  moqcache_append_exp(
      &hub->cache, t->cache_tag, group, o->object_id, o->payload,
      moqtrun_cache_exp(hub->cache.now, t->max_cache_ms));
}

/* ----- Malformed Track (draft-22 12.1 #4/#5; same list in 18/19) ----- */

int moqtrun_past_track_end(const wired_moqtrun_track* t, moqctl_loc l) {
  return (t->end_flags & 1) && moqctl_loc_less(t->track_end, l);
}

int moqtrun_past_group_end(const wired_moqtrun_track* t, moqctl_loc l) {
  return (t->end_flags & 2) && t->group_end.group == l.group &&
         t->group_end.object < l.object;
}
