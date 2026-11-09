#ifndef MOQCACHE_H
#define MOQCACHE_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * Object cache for FETCH (draft-ietf-moq-transport-19 10.12.3) in a
 * caller-provided arena. Records {tag, group, object, len, exp} + payload are
 * packed back to back in arrival order; tag names the track incarnation,
 * so several tracks share one arena and one oldest-first eviction order.
 *
 * A record may carry an expiry clock (moqcache_append_exp, draft-18 12.3
 * MAX_CACHE_DURATION): once moqcache.now reaches it, the record's whole
 * group becomes a tombstone (its state unknown) at the next lookup.
 *
 * Rules: a group is cached whole or not at all. An arriving Object evicts
 * the minimum number of whole OLDEST other groups it needs room for. A
 * group whose own bytes would exceed the arena (or an Object past
 * MOQCACHE_OBJ_MAX) is dropped whole and leaves a header-only tombstone,
 * so its later Objects are not cached either and FETCH reports it as an
 * unknown range. Evicting another track's still-open (newest) group
 * likewise leaves its tombstone, kept until that track moves on to a newer
 * group, so no group is ever cached partially. An arena smaller than
 * (open tracks + 1) * MOQCACHE_HDR may find no room even for a tombstone;
 * the arriving group is then dropped without one.
 *
 * ponytail: eviction compacts the arena (one memmove pass) and lookups
 * scan it linearly; a one-entry resume point lets a forward walk over one
 * tag continue where the last lookup stopped, so a FETCH costs O(arena)
 * per walk plus O(arena) per gap it crosses (the gap check rescans), not
 * per item. A ring with an index when arenas grow past a
 * few MB. Groups are assumed to arrive in ascending order per
 * track (an Object of an older group is cached as if it were new).
 */

/** Bytes of one record header (tag, group, object, len, exp as 5 u64). */
#define MOQCACHE_HDR 40

/** Largest cached payload: one fetch Object (payload + framing of at most
 * 64 bytes) must fit a single 64 KiB stream round. */
#define MOQCACHE_OBJ_MAX (65536 - 64)

/** Largest Object ID a Location can carry (a 62-bit varint, draft 1.4.1):
 * an unknown range ending at a whole group names this Object. */
#define MOQCACHE_OBJ_ID_MAX 0x3FFFFFFFFFFFFFFFULL

/** Fixed capacity: Gone ranges kept (draft-ietf-moq-transport-23 7.1),
 * all tracks. An upstream FETCH answer marks Gone at a publisher's
 * restart or retention boundary (2.1.2), so it carries one such range
 * at most, and WIRED_MOQTRUN_MAX_FETCHES (8) legs run at once: 16 keeps
 * two per leg. A full table drops its oldest range, which then reads
 * Unknown again -- never a wrong answer. */
#define MOQCACHE_GONE_MAX 16

/** One Gone range [lo, hi) of tag, kept while the cache clock is below
 * exp; exp 0 (a zeroed entry) is never live. */
typedef struct {
  /** The track incarnation (moqcache records' tag). */
  u64 tag;
  /** First Location of the range. */
  moqctl_loc lo;
  /** Location right after the range. */
  moqctl_loc hi;
  /** Clock (ms) at which the range reads Unknown again. */
  u64 exp;
} moqcache_gone;

/** A FETCH object cache over one caller-owned arena.
 * views: arena=caller */
typedef struct {
  /** Caller-provided storage; must outlive the cache. Not owned. */
  u8* arena;
  usz cap;  /**< arena bytes: the budget */
  usz used; /**< bytes of records held, from arena[0] */
  /** Resume point: the last lookup of hint_tag at hint_cur found
   * hint_off; 0 (scan from the start) after any record moved. */
  usz hint_off;
  /** The tag that lookup was for. */
  u64 hint_tag;
  /** The Location that lookup was for. */
  moqctl_loc hint_cur;
  /** The caller's clock (ms), set before appends and lookups. */
  u64 now;
  /** Earliest expiry of a held record, ~0 when none expires. */
  u64 next_exp;
  /** Gone ranges (moqcache_gone_add), overwritten oldest first. */
  moqcache_gone gone[MOQCACHE_GONE_MAX];
  /** Ranges added so far: the next one goes to gone[gone_at % max]. */
  usz gone_at;
} moqcache;

/** One FETCH response item at a cursor: an Object (unknown 0, payload a
 * view into the arena, valid until the next append/release) or an End of
 * Unknown Range whose last Location is loc. next is the Location after
 * the item. */
typedef struct {
  /** 1 for an End of Range (Unknown, or Gone when gone), 0 for a cached
   * Object. */
  int unknown;
  /** 1 when the range is a kept Gone range (moqcache_gone_add). */
  int gone;
  /** The Object's Location, or the unknown range's last Location. */
  moqctl_loc loc;
  /** Object payload (view into the arena, valid until the next
   * append/release); empty for an unknown range. */
  wired_span payload;
  /** Location right after this item: where the next lookup starts. */
  moqctl_loc next;
} moqcache_item;

/** An empty cache over arena[0..cap); cap 0 caches nothing. */
void moqcache_init(moqcache* c, u8* arena, usz cap);

/** Caches Object {group, object} of tag (rules above). */
void moqcache_append(
    moqcache* c, u64 tag, u64 group, u64 object, wired_span payload);

/** moqcache_append, the Object no longer served once now reaches exp
 * (~0: never). */
void moqcache_append_exp(
    moqcache* c, u64 tag, u64 group, u64 object, wired_span payload, u64 exp);

/** Drops tag's group, leaving its tombstone: the group reads as an
 * unknown range and takes no more Objects until the track moves on. */
void moqcache_kill(moqcache* c, u64 tag, u64 group);

/** Drops every record of tag (its publisher left). */
void moqcache_release(moqcache* c, u64 tag);

/** cur moved past Locations known not to exist (the rest of a cached
 * group), stopping at a cached Object, the next group, an unknown range
 * or end. */
moqctl_loc moqcache_skip(moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc end);

/** Keeps {lo}..{last} (inclusive) of tag as Gone until the clock reaches
 * exp (~0: never): an upstream End of Gone Range (draft-23 7.1, 10.3).
 * A cache with no arena keeps none. */
void moqcache_gone_add(
    moqcache* c, u64 tag, moqctl_loc lo, moqctl_loc last, u64 exp);

/** The item at cur (a moqcache_skip result below end). An unknown range
 * runs to the next cached group (or the end of a tombstoned group),
 * capped at end; a live Gone range at cur makes it Gone to that range's
 * end, one ahead stops it there (a cached Object stays an Object). */
void moqcache_item_at(
    moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc end, moqcache_item* it);

#endif
