#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_relay_save_hdr(wired_moqtrun_relay* relay, wired_span data);
static void moqtrun_relay_claim_init(
    wired_moqtrun_relay*       relay,
    const wired_moqtrun_track* track,
    u64                        pub_stream_id);
static void moqtrun_relay_head_init(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    usz                  whole_end);
static int moqtrun_cacheable(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 status);
static int moqtrun_group_closed(const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_gone_on(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);
static int moqtrun_cache_says_gone(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l);

/* The stream's Subgroup ID and Publisher Priority kept for late opens and
 * the Range Filter gate (moqtrun_stream_keys). ponytail: a mode-0b01
 * stream whose first delivery tore inside its first Object saves no
 * header, so late joiners of that stream are skipped; resolve it on the
 * next delivery if that matters. */
static void moqtrun_relay_save_hdr(
    wired_moqtrun_relay* relay, wired_span data) {
  usz            off = 0;
  moqdata_subhdr hdr;
  relay->hdr_len = 0;
  if (!moqtrun_stream_keys(
          data, relay->default_pub_prio, &relay->subgroup_id,
          &relay->pub_prio)) {
    return;
  }
  if (moqdata_subhdr_take(data, &off, &hdr) != MOQDATA_OK) {
    return;
  }
  moqtrun_relay_save_hdr_raw(relay, data, off);
}

/* Starts relaying a fresh publisher stream that stays open past this call
 * (fin=0): claims a relay entry keyed by pub_stream_id and opens one
 * keep-open uni stream per subscriber carrying wire as the first round.
 * Every entry busy -> this stream is not relayed at all (its subscribers
 * miss it; WIRED_MOQTRUN_MAX_RELAYS is sized so this only happens under a
 * burst the room's own pacing never produces). A reliable track's stream
 * (moqtrun_rel_start) additionally binds a ring and records each opened
 * subscriber stream as a ring cursor (moqtrun_rel_attach_subs); the open
 * calls themselves are shared with the lossy path. */
/* A just-claimed relay entry for pub_stream_id, lossy and with no
 * subscriber stream open yet. */
static void moqtrun_relay_claim_init(
    wired_moqtrun_relay*       relay,
    const wired_moqtrun_track* track,
    u64                        pub_stream_id) {
  relay->in_use           = 1;
  relay->default_pub_prio = track->default_pub_prio;
  relay->pub_stream_id    = pub_stream_id;
  relay->rel_idx          = -1; /* lossy until moqtrun_rel_start binds a ring */
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    relay->sub_stream_set[i]  = 0;
    relay->sub_busy_streak[i] = 0; /* freestanding memory starts unzeroed */
  }
  moqtrun_frag_release(relay);
}

/* relay's per-stream state from its first delivery wire, whole Objects up
 * to whole_end: the held tail and the saved SUBGROUP_HEADER. */
static void moqtrun_relay_head_init(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    usz                  whole_end) {
  relay->sub_expired = 0;
  relay->sub_reframe = 0;
  relay->subgroup_id = 0;
  relay->pub_prio    = relay->default_pub_prio;
  moqtrun_relay_save_frag(
      hub, relay, wire.p + whole_end, wire.n - whole_end,
      hub->live.last_now_ms);
  moqtrun_relay_save_hdr(relay, wire);
}

void moqtrun_relay_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           wire,
    usz                  whole_end) {
  wired_moqtrun_relay* relay = moqtrun_relay_alloc(track);
  if (!relay) {
    hub->stat_relay_full++; /* whole message lost for every subscriber */
    return;
  }
  moqtrun_relay_claim_init(relay, track, pub_stream_id);
  moqtrun_rel_start(
      hub, track, relay, pub_wt, pub_stream_id,
      wired_span_of(wire.p, whole_end));
  moqtrun_relay_head_init(hub, relay, wire, whole_end);
  moqtrun_subgroup_scan(
      wired_span_of(wire.p, whole_end), 0, &relay->seq, &relay->group_id);
  moqtss_prime(hub, track, relay->group_id); /* SSTS (moqtssts_run.c) */
  moqtrun_relay_open_all(hub, track, relay, wired_span_of(wire.p, whole_end));
  moqtrun_rel_attach_subs(hub, track, relay);
  moqtrun_relay_end_poisoned(hub, track, relay, 0);
}

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
 * cached Group, or a Group between cached ones). */
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

/* shortcut: a Subgroup stream's Objects are forwarded as the stream's
 * bytes, so only caching and datagram Objects are gated; cutting one out
 * of a stream needs its successor's Object ID Delta rewritten. */
int moqtrun_obj_gone(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, moqctl_loc l) {
  return hub && t && moqtrun_gone_on(hub, t, l);
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
  if (!moqtrun_cacheable(hub, t, o->status) ||
      moqtrun_obj_gone(hub, t, moqctl_loc_of(group, o->object_id))) {
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
