#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_track_return_rings(
    wired_moqt_hub* hub, wired_moqtrun_track* t);
static void moqtrun_track_keep_counts(
    wired_moqt_hub* hub, const wired_moqtrun_track* t);
static wired_moqtrun_track* moqtrun_other_track_for_name(
    wired_moqt_hub* hub, usz i, usz pub_idx, moqtrun_key k);
static int moqtrun_newer_owner(
    wired_moqt_hub* hub, usz i, usz pub_idx, moqtrun_key k);
static int moqtrun_newer_holds_name(
    wired_moqt_hub* hub, usz pub_idx, moqtrun_key k);

void moqtrun_track_claim(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqtrun_key          k,
    u64                  track_alias) {
  /* Reset every orphaned relay stream BEFORE clear_subs deactivates the
   * very subs[] entries this walk reads (moqtrun_track_reset_stale_relays'
   * own doc) -- a fresh claim (in_use was 0, e.g. after a reconnect that
   * re-initialized this peer's whole tracks[]) always clears subs, whether
   * or not the publisher rejoining is who they used to be; the reattach
   * that follows in moqtrun_handle_publish re-derives who to reattach from
   * each SUBSCRIBER's own surviving sub_names ring instead. */
  moqtrun_track_reset_stale_relays(hub, t);
  moqtrun_track_cache_drop(hub, t);
  if (!t->in_use) {
    moqtrun_track_clear_subs(t);
  }
  t->cache_tag        = ++hub->cache_tag_next;
  t->in_use           = 1;
  t->default_pub_prio = 128; /* hub-owned tracks; moqtrun_track_open reads */
  t->own_alias        = track_alias;
  t->has_largest      = 0; /* a new PUBLISH restarts the Largest */
  t->end_flags        = 0;
  t->malformed        = 0;
  t->props_len        = 0;
  moqtrun_track_drop_rings(hub, t);
  moqtrun_track_clear_relays(t);
  moqtrun_record_track_key(t, k);
}

/* Returns relay r's bound ring to the pool AND releases the publisher
 * credit hold it may have placed (moqtrun_rel_return_ring). Unlike
 * moqtrun_rel_drop_ring's io-free teardown, a superseded publisher's
 * session is still live: a hold left on its stream would freeze it. */
void moqtrun_relay_return_ring(wired_moqt_hub* hub, wired_moqtrun_relay* r) {
  if (!r->in_use || r->rel_idx < 0) {
    return;
  }
  moqtrun_rel_return_ring(hub, r, &hub->rel_pool[r->rel_idx]);
}

static void moqtrun_track_return_rings(
    wired_moqt_hub* hub, wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    moqtrun_relay_return_ring(hub, &t->relays[r]);
  }
}

/* Each still-active subscriber's Stream Count survives into the state a
 * re-attach starts from (PUBLISH_DONE Stream Count, draft-22 9.9). */
static void moqtrun_track_keep_counts(
    wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    if (t->subs[si].active) {
      moqtrun_rp_keep_count(hub, &t->subs[si]);
    }
  }
}

/* Frees a superseded track: its subscribers' still-open relay streams are
 * reset (moqtrun_track_reset_stale_relays' own doc), its fills reset
 * INTERNAL_ERROR as upstream failures (ruling Q-08, in
 * moqtrun_track_cache_drop), its rings go back to the pool (holds
 * released), and the slot stops matching any name or Track Alias, so the
 * lingering session's stray Objects are dropped instead of relayed. */
void moqtrun_track_retire(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  moqtrun_track_keep_counts(hub, t);
  moqtrun_track_reset_stale_relays(hub, t);
  moqtrun_track_cache_drop(hub, t);
  moqtrun_track_return_rings(hub, t);
  moqtrun_track_clear_relays(t);
  moqtrun_subtracks_track_gone(hub, t->cache_tag);
  t->in_use = 0;
}

/* Peer i's track keyed k, unless i is the publisher itself. */
static wired_moqtrun_track* moqtrun_other_track_for_name(
    wired_moqt_hub* hub, usz i, usz pub_idx, moqtrun_key k) {
  return i != pub_idx ? moqtrun_peer_track_for_name(&hub->peers[i], k) : 0;
}

/* 1 iff peer i, a NEWER session than the publisher (higher join_seq),
 * already holds a track named name. */
static int moqtrun_newer_owner(
    wired_moqt_hub* hub, usz i, usz pub_idx, moqtrun_key k) {
  return moqtrun_other_track_for_name(hub, i, pub_idx, k) != 0 &&
         hub->peers[i].join_seq > hub->peers[pub_idx].join_seq;
}

static int moqtrun_newer_holds_name(
    wired_moqt_hub* hub, usz pub_idx, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_newer_owner(hub, i, pub_idx, k)) {
      return 1;
    }
  }
  return 0;
}

/* Name ownership policy (no auth on PUBLISH): the NEWEST session holding
 * a name owns it -- the same participant id opened in two tabs means the
 * newer tab wins. A participant that rejoins while its old session still
 * lingers (no clean close reached the hub, so it stays until the idle
 * timeout) PUBLISHes the same name twice; every OLDER peer's same-name
 * track is retired, so SUBSCRIBE resolves to the live track only and the
 * old track's subscribers follow via moqtrun_reattach_subs. Callers first
 * refuse a PUBLISH a newer peer already owns (moqtrun_publish_slot), so
 * arrival order never lets a stale session take the name back. */
void moqtrun_supersede_name(wired_moqt_hub* hub, usz pub_idx, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_track* t = moqtrun_other_track_for_name(hub, i, pub_idx, k);
    if (t) {
      moqtrun_track_retire(hub, t);
    }
  }
}

/* p's slot for a PUBLISH of name (moqtrun_track_alloc_slot), or 0 when
 * a newer session already owns name. Refusing -- rather than accepting
 * without superseding -- keeps every name on at most one live track: two
 * would make SUBSCRIBE resolve by peer-slot order, the stale-mapping bug
 * moqtrun_supersede_name exists to prevent. The refused, older session is
 * stale by definition (its client has moved on to the newer one). */
wired_moqtrun_track* moqtrun_publish_slot(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, moqtrun_key k) {
  if (moqtrun_key_oversized(k)) {
    return 0;
  }
  if (moqtrun_newer_holds_name(hub, peer_idx, k)) {
    return 0;
  }
  return moqtrun_track_alloc_slot(p, k);
}

int moqtrun_prop_is_num(const moqkvp* kv, u64 type) {
  return kv->type == type && !kv->is_raw;
}

u64 moqtrun_prop_num_of(const moqkvp* kv, u64 type, u64 prior) {
  return moqtrun_prop_is_num(kv, type) ? kv->num : prior;
}
