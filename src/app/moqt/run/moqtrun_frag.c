#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_frag_slot_free(const wired_moqt_hub* hub, usz i);
static i32 moqtrun_frag_take_free(wired_moqt_hub* hub, wired_moqtrun_relay* r);
static i32 moqtrun_frag_slot_for(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz n);
static u64 moqtrun_relay_born(const wired_moqtrun_relay* r, u64 now);
static u64 moqtrun_tail_born(usz off, u64 now, u64 born);

static int moqtrun_frag_slot_free(const wired_moqt_hub* hub, usz i) {
  const wired_moqtrun_relay* o = hub->frag_owner[i];
  return !o || !o->in_use || o->frag_idx != (i32)i;
}

static i32 moqtrun_frag_take_free(wired_moqt_hub* hub, wired_moqtrun_relay* r) {
  for (usz i = 0; i < WIRED_MOQTRUN_FRAG_POOL; i++) {
    if (moqtrun_frag_slot_free(hub, i)) {
      hub->frag_owner[i] = r;
      return (i32)i;
    }
  }
  return -1;
}

/* The pool buffer that will hold an n-byte fragment for relay: the one it
 * already holds, else a free one; -1 when n is over the limit or the pool
 * is exhausted. */
static i32 moqtrun_frag_slot_for(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz n) {
  if (n >= WIRED_MOQTRUN_RELAY_FRAG_MAX) {
    return -1;
  }
  if (relay->frag_idx >= 0) {
    return relay->frag_idx;
  }
  return moqtrun_frag_take_free(hub, relay);
}

int moqtrun_relay_poisoned(const wired_moqtrun_relay* relay) {
  return relay->frag_idx == MOQTRUN_FRAG_POISONED;
}

/* Gives relay's fragment buffer (if any) back to the pool. */
void moqtrun_frag_release(wired_moqtrun_relay* relay) {
  relay->frag_idx = -1;
  relay->frag_len = 0;
}

/* Teardown-side release: a poisoned relay holds no buffer, and keeps its
 * mark so it stays sunk (moqtrun_relay_sink) instead of decoding again.
 * An unused entry is skipped: its fields may never have been written, and
 * its buffer already counts as free (moqtrun_frag_slot_free). */
void moqtrun_frag_release_unless_poisoned(wired_moqtrun_relay* relay) {
  if (relay->in_use && !moqtrun_relay_poisoned(relay)) {
    moqtrun_frag_release(relay);
  }
}

/* An n-byte tail with no buffer to wait in is dropped: counted, and the
 * relay poisoned (moqtrun_relay_end_poisoned ends its subscriber side). */
void moqtrun_frag_drop(wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz n) {
  if (n == 0) {
    return;
  }
  relay->frag_idx = MOQTRUN_FRAG_POISONED;
  hub->stat_frag_drop++;
}

/* Saves the undelivered tail (bytes past the last complete Object) as the
 * relay's fragment for the next delivery, in a buffer from the hub's
 * shared pool (released once nothing is held). A tail of
 * WIRED_MOQTRUN_RELAY_FRAG_MAX bytes or more belongs to an Object over the
 * relayable limit and can never complete, and one finding the pool
 * exhausted has nowhere to wait -- both are dropped (counted on the hub)
 * and the relay is poisoned: everything after the tail starts mid-Object,
 * so the stream relays nothing more (moqtrun_relay_continue). */
void moqtrun_relay_save_frag(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    const u8*            p,
    usz                  n,
    u64                  born_ms) {
  i32 slot = n ? moqtrun_frag_slot_for(hub, relay, n) : -1;
  moqtrun_frag_release(relay);
  if (slot < 0) {
    moqtrun_frag_drop(hub, relay, n);
    return;
  }
  bytes_memcpy(hub->frag_pool[slot], p, n);
  relay->frag_idx = slot;
  relay->frag_len = n;
  relay->frag_ms  = born_ms;
}

/* Arrival of the first byte a delivery's whole Objects start with: the
 * held fragment's, else now.
 *
 * ponytail: decode is atomic per Object (moqdata_obj_take reads header and
 * payload together), so this hub has no observable moment between "an
 * Object's header finished" and "its payload started" -- only "this
 * Object's leading byte arrived". draft-19's "first payload byte" and
 * draft-22's "last header byte" start points collapse to that same moment
 * here; add per-Object header/payload split tracking if a version gate
 * between them is ever needed. */
static u64 moqtrun_relay_born(const wired_moqtrun_relay* r, u64 now) {
  return r->frag_len ? r->frag_ms : now;
}

/* Arrival of the tail held after a delivery whose whole Objects end at
 * off: a held fragment is under one Object, so past a whole one the tail
 * starts in this delivery (now); with none it still starts at born. */
static u64 moqtrun_tail_born(usz off, u64 now, u64 born) {
  return off ? now : born;
}

/* Object-boundary normalization (wired_moqtrun_relay's frag doc): prepends
 * the relay's held fragment to this delivery in hub->relay_scratch, finds
 * the last complete Object boundary, keeps the tail past it as the next
 * fragment, and returns the whole-Objects prefix -- the only bytes safe to
 * forward, because a forwarded round can be dropped per subscriber and a
 * dropped round must never end mid-Object. Decoding continues the
 * stream's own Object sequence (relay->seq, set from its SUBGROUP_HEADER
 * by moqtrun_relay_start), so each Object's ID counts toward the track's
 * Largest. *seq0_out receives the chaining state as it was BEFORE this
 * round's decode (relay->seq is advanced in place past it) -- a caller
 * cutting the returned span to one subscriber's End Object re-decodes
 * from this same starting point (moqtrun_wire_cutoff). */
wired_span moqtrun_relay_normalize(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           data,
    u64*                 born_ms,
    moqdata_objseq*      seq0_out) {
  u64 now   = hub->live.last_now_ms;
  usz total = relay->frag_len + data.n;
  usz off   = 0;
  *born_ms  = moqtrun_relay_born(relay, now);
  if (relay->frag_len) {
    bytes_memcpy(
        hub->relay_scratch, hub->frag_pool[relay->frag_idx], relay->frag_len);
  }
  bytes_memcpy(hub->relay_scratch + relay->frag_len, data.p, data.n);
  *seq0_out = relay->seq;
  moqtrun_decode_object_loop(
      hub, wired_span_of(hub->relay_scratch, total), &off, &relay->seq,
      relay->group_id, track);
  moqtrun_relay_save_frag(
      hub, relay, hub->relay_scratch + off, total - off,
      moqtrun_tail_born(off, now, *born_ms));
  return wired_span_of(hub->relay_scratch, off);
}
