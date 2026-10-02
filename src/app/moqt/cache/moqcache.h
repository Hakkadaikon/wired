#ifndef MOQCACHE_H
#define MOQCACHE_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * Object cache for FETCH (draft-ietf-moq-transport-19 10.12.3) in a
 * caller-provided arena. Records {tag, group, object, len} + payload are
 * packed back to back in arrival order; tag names the track incarnation,
 * so several tracks share one arena and one oldest-first eviction order.
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
 * scan it linearly -- O(arena) per call; a ring with an index when arenas
 * grow past a few MB. Groups are assumed to arrive in ascending order per
 * track (an Object of an older group is cached as if it were new).
 */

/** Bytes of one record header (tag, group, object, len as 4 u64). */
#define MOQCACHE_HDR 32

/** Largest cached payload: one fetch Object (payload + framing of at most
 * 64 bytes) must fit a single 64 KiB stream round. */
#define MOQCACHE_OBJ_MAX (65536 - 64)

/** Largest Object ID a Location can carry (a 62-bit varint, draft 1.4.1):
 * an unknown range ending at a whole group names this Object. */
#define MOQCACHE_OBJ_ID_MAX 0x3FFFFFFFFFFFFFFFULL

typedef struct {
  u8* arena;
  usz cap;  /**< arena bytes: the budget */
  usz used; /**< bytes of records held, from arena[0] */
} moqcache;

/** One FETCH response item at a cursor: an Object (unknown 0, payload a
 * view into the arena, valid until the next append/release) or an End of
 * Unknown Range whose last Location is loc. next is the Location after
 * the item. */
typedef struct {
  int        unknown;
  moqctl_loc loc;
  wired_span payload;
  moqctl_loc next;
} moqcache_item;

/** An empty cache over arena[0..cap); cap 0 caches nothing. */
void moqcache_init(moqcache* c, u8* arena, usz cap);

/** Caches Object {group, object} of tag (rules above). */
void moqcache_append(
    moqcache* c, u64 tag, u64 group, u64 object, wired_span payload);

/** Drops every record of tag (its publisher left). */
void moqcache_release(moqcache* c, u64 tag);

/** cur moved past Locations known not to exist (the rest of a cached
 * group, groups between cached ones), stopping at a cached Object, an
 * unknown range or end. */
moqctl_loc moqcache_skip(
    const moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc end);

/** The item at cur (a moqcache_skip result below end). An unknown range
 * runs to the next cached group (or the end of a tombstoned group),
 * capped at end. */
void moqcache_item_at(
    const moqcache* c,
    u64             tag,
    moqctl_loc      cur,
    moqctl_loc      end,
    moqcache_item*  it);

#endif
