#include "app/moqt/cache/moqcache_impl.h"

static int  moqcache_evict_one(moqcache* c, u64 tag, u64 group);
static void moqcache_make_room(moqcache* c, moqcache_rec r, usz need);
static int  moqcache_put(moqcache* c, moqcache_rec r, const u8* p, usz len);
static usz  moqcache_group_bytes(
    const moqcache* c, u64 tag, u64 group, int* dead);
static void moqcache_kill(moqcache* c, u64 tag, u64 group);
static int  moqcache_too_big(usz group_bytes, usz n, usz cap);
static int  moqcache_store(
    moqcache* c, moqcache_rec r, wired_span payload, usz held);

/* Evicts the oldest whole group other than tag's group; 0 if none can
 * go. A closed group goes whole; an open one (another track's group
 * still arriving) becomes a tombstone, so it is never left partial. */
static int moqcache_evict_one(moqcache* c, u64 tag, u64 group) {
  usz off = moqcache_first_victim(c, tag, group);
  if (off == c->used) {
    return 0;
  }
  moqcache_rec r = moqcache_rec_at(c, off);
  if (moqcache_stays_open(c, r, tag, group)) {
    moqcache_entomb(c, r.tag, r.group);
    return 1;
  }
  moqcache_drop(c, r.tag, r.group, 0);
  return 1;
}

/* Evicts the fewest oldest groups other than r's for need more bytes. */
static void moqcache_make_room(moqcache* c, moqcache_rec r, usz need) {
  while (c->used + need > c->cap && moqcache_evict_one(c, r.tag, r.group)) {
  }
}

/* Writes r (+ len bytes at p) after evicting just enough older groups;
 * 0 when it cannot fit (open groups' tombstones hold the rest). */
static int moqcache_put(moqcache* c, moqcache_rec r, const u8* p, usz len) {
  usz need = MOQCACHE_HDR + len;
  if (need > c->cap) {
    return 0;
  }
  moqcache_make_room(c, r, need);
  if (c->used + need > c->cap) {
    return 0;
  }
  moqcache_write(c, r, p, len);
  return 1;
}

/* Bytes tag's group holds; *dead set when it is a tombstone. */
static usz moqcache_group_bytes(
    const moqcache* c, u64 tag, u64 group, int* dead) {
  usz n = 0;
  for (usz off = 0; off < c->used;
       off += moqcache_rec_size(moqcache_rec_at(c, off))) {
    moqcache_rec r = moqcache_rec_at(c, off);
    if (!moqcache_hit(r, tag, group, 0)) {
      continue;
    }
    *dead |= moqcache_dead(r);
    n += moqcache_rec_size(r);
  }
  return n;
}

/* The group cannot be held whole: drop it and leave a tombstone (none
 * when not even that fits -- the arena is below the ceiling in
 * moqcache.h). */
static void moqcache_kill(moqcache* c, u64 tag, u64 group) {
  moqcache_rec t = {tag, group, 0, MOQCACHE_DEAD};
  moqcache_drop(c, tag, group, 0);
  moqcache_put(c, t, 0, 0);
}

static int moqcache_too_big(usz group_bytes, usz n, usz cap) {
  return n > MOQCACHE_OBJ_MAX || group_bytes + MOQCACHE_HDR + n > cap;
}

/* Caches r unless its group could then no longer be held whole. */
static int moqcache_store(
    moqcache* c, moqcache_rec r, wired_span payload, usz held) {
  return !moqcache_too_big(held, payload.n, c->cap) &&
         moqcache_put(c, r, payload.p, payload.n);
}

void moqcache_append(
    moqcache* c, u64 tag, u64 group, u64 object, wired_span payload) {
  int          dead = 0;
  usz          held = moqcache_group_bytes(c, tag, group, &dead);
  moqcache_rec r    = {tag, group, object, payload.n};
  if (dead) {
    return;
  }
  if (!moqcache_store(c, r, payload, held)) {
    moqcache_kill(c, tag, group);
  }
}
