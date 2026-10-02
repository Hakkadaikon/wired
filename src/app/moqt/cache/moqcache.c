#include "app/moqt/cache/moqcache.h"

#include "common/bytes/util/bytes.h"

/* Record layout (moqcache.h): this header, then len payload bytes. A
 * tombstone (a dropped group) has len MOQCACHE_DEAD and no payload. */
typedef struct {
  u64 tag;
  u64 group;
  u64 object;
  u64 len;
} moqcache_rec;

#define MOQCACHE_DEAD (~(u64)0)

void moqcache_init(moqcache* c, u8* arena, usz cap) {
  c->arena = arena;
  c->cap   = cap;
  c->used  = 0;
}

static moqcache_rec moqcache_rec_at(const moqcache* c, usz off) {
  moqcache_rec r;
  bytes_memcpy(&r, c->arena + off, sizeof r);
  return r;
}

static int moqcache_dead(moqcache_rec r) { return r.len == MOQCACHE_DEAD; }

static usz moqcache_rec_size(moqcache_rec r) {
  return MOQCACHE_HDR + (moqcache_dead(r) ? 0 : (usz)r.len);
}

/* r belongs to tag's group (any group when any). */
static int moqcache_hit(moqcache_rec r, u64 tag, u64 group, int any) {
  return r.tag == tag && (any || r.group == group);
}

/* Removes the matching records, sliding the rest down (forward copy:
 * the destination never passes the source). */
static void moqcache_drop(moqcache* c, u64 tag, u64 group, int any) {
  usz w = 0, off = 0;
  while (off < c->used) {
    moqcache_rec r  = moqcache_rec_at(c, off);
    usz          sz = moqcache_rec_size(r);
    if (!moqcache_hit(r, tag, group, any)) {
      bytes_memcpy(c->arena + w, c->arena + off, sz);
      w += sz;
    }
    off += sz;
  }
  c->used = w;
}

void moqcache_release(moqcache* c, u64 tag) { moqcache_drop(c, tag, 0, 1); }

/* Offset of the first record not in tag's group, else c->used. */
static usz moqcache_first_other(const moqcache* c, u64 tag, u64 group) {
  usz off = 0;
  while (off < c->used && moqcache_hit(moqcache_rec_at(c, off), tag, group, 0))
    off += moqcache_rec_size(moqcache_rec_at(c, off));
  return off;
}

/* Evicts the oldest whole group other than tag's group; 0 if none. */
static int moqcache_evict_one(moqcache* c, u64 tag, u64 group) {
  usz off = moqcache_first_other(c, tag, group);
  if (off == c->used) return 0;
  moqcache_rec r = moqcache_rec_at(c, off);
  moqcache_drop(c, r.tag, r.group, 0);
  return 1;
}

/* Evicts the fewest oldest groups other than r's for need more bytes. */
static void moqcache_make_room(moqcache* c, moqcache_rec r, usz need) {
  while (c->used + need > c->cap && moqcache_evict_one(c, r.tag, r.group)) {
  }
}

/* Writes r (+ len bytes at p) after evicting just enough older groups. */
static void moqcache_put(moqcache* c, moqcache_rec r, const u8* p, usz len) {
  usz need = MOQCACHE_HDR + len;
  if (need > c->cap) return;
  moqcache_make_room(c, r, need);
  bytes_memcpy(c->arena + c->used, &r, sizeof r);
  bytes_memcpy(c->arena + c->used + MOQCACHE_HDR, p, len);
  c->used += need;
}

/* Bytes tag's group holds; *dead set when it is a tombstone. */
static usz moqcache_group_bytes(
    const moqcache* c, u64 tag, u64 group, int* dead) {
  usz n = 0;
  for (usz off = 0; off < c->used;
       off += moqcache_rec_size(moqcache_rec_at(c, off))) {
    moqcache_rec r = moqcache_rec_at(c, off);
    if (!moqcache_hit(r, tag, group, 0)) continue;
    *dead |= moqcache_dead(r);
    n += moqcache_rec_size(r);
  }
  return n;
}

/* The group cannot be held whole: drop it and leave a tombstone. */
static void moqcache_kill(moqcache* c, u64 tag, u64 group) {
  moqcache_rec t = {tag, group, 0, MOQCACHE_DEAD};
  moqcache_drop(c, tag, group, 0);
  moqcache_put(c, t, 0, 0);
}

static int moqcache_too_big(usz group_bytes, usz n, usz cap) {
  return n > MOQCACHE_OBJ_MAX || group_bytes + MOQCACHE_HDR + n > cap;
}

void moqcache_append(
    moqcache* c, u64 tag, u64 group, u64 object, wired_span payload) {
  int          dead = 0;
  usz          held = moqcache_group_bytes(c, tag, group, &dead);
  moqcache_rec r    = {tag, group, object, payload.n};
  if (dead) return;
  if (moqcache_too_big(held, payload.n, c->cap)) {
    moqcache_kill(c, tag, group);
    return;
  }
  moqcache_put(c, r, payload.p, payload.n);
}

/* ===== FETCH items ===== */

static moqctl_loc moqcache_loc(u64 group, u64 object) {
  moqctl_loc l = {group, object};
  return l;
}

/* First / last Location r stands for (a tombstone: its whole group). */
static moqctl_loc moqcache_rec_first(moqcache_rec r) {
  return moqcache_loc(r.group, moqcache_dead(r) ? 0 : r.object);
}

static moqctl_loc moqcache_rec_last(moqcache_rec r) {
  return moqcache_loc(
      r.group, moqcache_dead(r) ? MOQCACHE_OBJ_ID_MAX : r.object);
}

static int moqcache_at_or_after(moqcache_rec r, u64 tag, moqctl_loc cur) {
  return r.tag == tag && !moqctl_loc_less(moqcache_rec_last(r), cur);
}

/* Offset of tag's first record reaching cur (records of one tag are in
 * ascending order), else c->used. */
static usz moqcache_find(const moqcache* c, u64 tag, moqctl_loc cur) {
  usz off = 0;
  while (off < c->used &&
         !moqcache_at_or_after(moqcache_rec_at(c, off), tag, cur))
    off += moqcache_rec_size(moqcache_rec_at(c, off));
  return off;
}

/* cur's group is not older than tag's oldest cached group: every
 * Location there is either cached, tombstoned or nonexistent (groups are
 * cached whole and evicted oldest first). */
static int moqcache_covered(const moqcache* c, u64 tag, moqctl_loc cur) {
  usz off = moqcache_find(c, tag, moqcache_loc(0, 0));
  return off < c->used && moqcache_rec_at(c, off).group <= cur.group;
}

static int moqcache_holds(const moqcache* c, usz off, moqctl_loc cur) {
  return off < c->used &&
         !moqctl_loc_less(cur, moqcache_rec_first(moqcache_rec_at(c, off)));
}

static moqctl_loc moqcache_min(moqctl_loc a, moqctl_loc b) {
  return moqctl_loc_less(a, b) ? a : b;
}

/* Where a skipped (nonexistent) stretch ends. */
static moqctl_loc moqcache_gap_end(const moqcache* c, usz off, moqctl_loc end) {
  if (off == c->used) return end;
  return moqcache_min(moqcache_rec_first(moqcache_rec_at(c, off)), end);
}

moqctl_loc moqcache_skip(
    const moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc end) {
  usz off = moqcache_find(c, tag, cur);
  if (moqcache_holds(c, off, cur) || !moqcache_covered(c, tag, cur)) return cur;
  return moqcache_gap_end(c, off, end);
}

static int moqcache_is_obj(moqcache_rec r, moqctl_loc cur) {
  return !moqcache_dead(r) && r.group == cur.group && r.object == cur.object;
}

/* End (exclusive) of the unknown range at cur: a tombstone's group ends
 * at the next group, anything else at the next record's group. */
static moqctl_loc moqcache_unknown_stop(
    const moqcache* c, usz off, moqctl_loc end) {
  if (off == c->used) return end;
  moqcache_rec r = moqcache_rec_at(c, off);
  return moqcache_min(moqcache_loc(r.group + moqcache_dead(r), 0), end);
}

/* The Location just before stop (stop > {0, 0}). */
static moqctl_loc moqcache_prev(moqctl_loc stop) {
  if (stop.object) return moqcache_loc(stop.group, stop.object - 1);
  return moqcache_loc(stop.group - 1, MOQCACHE_OBJ_ID_MAX);
}

void moqcache_item_at(
    const moqcache* c,
    u64             tag,
    moqctl_loc      cur,
    moqctl_loc      end,
    moqcache_item*  it) {
  usz off = moqcache_find(c, tag, cur);
  bytes_memset(it, 0, sizeof *it);
  if (off < c->used && moqcache_is_obj(moqcache_rec_at(c, off), cur)) {
    moqcache_rec r = moqcache_rec_at(c, off);
    it->loc        = cur;
    it->payload    = wired_span_of(c->arena + off + MOQCACHE_HDR, r.len);
    it->next       = moqcache_loc(cur.group, cur.object + 1);
    return;
  }
  it->unknown = 1;
  it->next    = moqcache_unknown_stop(c, off, end);
  it->loc     = moqcache_prev(it->next);
}
