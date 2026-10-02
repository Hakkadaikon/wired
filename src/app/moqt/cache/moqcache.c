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

/* Removes the matching records, sliding the rest down. */
static void moqcache_drop(moqcache* c, u64 tag, u64 group, int any) {
  usz w = 0, off = 0;
  while (off < c->used) {
    moqcache_rec r  = moqcache_rec_at(c, off);
    usz          sz = moqcache_rec_size(r);
    if (!moqcache_hit(r, tag, group, any)) {
      bytes_move_down(c->arena + w, c->arena + off, sz);
      w += sz;
    }
    off += sz;
  }
  c->used = w;
}

void moqcache_release(moqcache* c, u64 tag) { moqcache_drop(c, tag, 0, 1); }

/* Appends r (+ len bytes at p); the caller made room. */
static void moqcache_write(moqcache* c, moqcache_rec r, const u8* p, usz len) {
  bytes_memcpy(c->arena + c->used, &r, sizeof r);
  bytes_memcpy(c->arena + c->used + MOQCACHE_HDR, p, len);
  c->used += MOQCACHE_HDR + len;
}

static int moqcache_later(moqcache_rec r, moqcache_rec v) {
  return r.tag == v.tag && r.group > v.group;
}

/* v's group is its track's newest, i.e. still open: more of its Objects
 * may arrive. */
static int moqcache_open(const moqcache* c, moqcache_rec v) {
  for (usz off = 0; off < c->used;
       off += moqcache_rec_size(moqcache_rec_at(c, off)))
    if (moqcache_later(moqcache_rec_at(c, off), v)) return 0;
  return 1;
}

/* v stays open once an Object of tag's group is stored: it is its
 * track's newest group and the arriving Object does not start a newer
 * group of that track. */
static int moqcache_stays_open(
    const moqcache* c, moqcache_rec v, u64 tag, u64 group) {
  return !(v.tag == tag && group > v.group) && moqcache_open(c, v);
}

/* r may be evicted for an Object of tag's group: another group, and not
 * an open group's tombstone (which keeps that group's later Objects out
 * until the group closes). */
static int moqcache_victim(
    const moqcache* c, moqcache_rec r, u64 tag, u64 group) {
  return !moqcache_hit(r, tag, group, 0) &&
         !(moqcache_dead(r) && moqcache_stays_open(c, r, tag, group));
}

static usz moqcache_first_victim(const moqcache* c, u64 tag, u64 group) {
  usz off = 0;
  while (off < c->used &&
         !moqcache_victim(c, moqcache_rec_at(c, off), tag, group))
    off += moqcache_rec_size(moqcache_rec_at(c, off));
  return off;
}

/* Replaces a cached group by its tombstone, in place of its bytes (a
 * group holds at least one record, so the tombstone always fits). */
static void moqcache_entomb(moqcache* c, u64 tag, u64 group) {
  moqcache_rec t = {tag, group, 0, MOQCACHE_DEAD};
  moqcache_drop(c, tag, group, 0);
  moqcache_write(c, t, 0, 0);
}

/* Evicts the oldest whole group other than tag's group; 0 if none can
 * go. A closed group goes whole; an open one (another track's group
 * still arriving) becomes a tombstone, so it is never left partial. */
static int moqcache_evict_one(moqcache* c, u64 tag, u64 group) {
  usz off = moqcache_first_victim(c, tag, group);
  if (off == c->used) return 0;
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
  if (need > c->cap) return 0;
  moqcache_make_room(c, r, need);
  if (c->used + need > c->cap) return 0;
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
    if (!moqcache_hit(r, tag, group, 0)) continue;
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
  if (dead) return;
  if (!moqcache_store(c, r, payload, held)) moqcache_kill(c, tag, group);
}

/* ===== FETCH items ===== */

/* First / last Location r stands for (a tombstone: its whole group). */
static moqctl_loc moqcache_rec_first(moqcache_rec r) {
  return moqctl_loc_of(r.group, moqcache_dead(r) ? 0 : r.object);
}

static moqctl_loc moqcache_rec_last(moqcache_rec r) {
  return moqctl_loc_of(
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
  usz off = moqcache_find(c, tag, moqctl_loc_of(0, 0));
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
 * at the next group, anything else at the next record's group. Never at
 * or before cur, so a cursor only moves forward (a cached group is never
 * partial, so this only guards that invariant). */
static moqctl_loc moqcache_unknown_stop(
    const moqcache* c, usz off, moqctl_loc cur, moqctl_loc end) {
  moqctl_loc stop = end;
  if (off < c->used)
    stop = moqctl_loc_of(
        moqcache_rec_at(c, off).group + moqcache_dead(moqcache_rec_at(c, off)),
        0);
  if (!moqctl_loc_less(cur, stop))
    stop = moqctl_loc_of(cur.group, cur.object + 1);
  return moqcache_min(stop, end);
}

/* The Location just before stop (stop > {0, 0}). */
static moqctl_loc moqcache_prev(moqctl_loc stop) {
  if (stop.object) return moqctl_loc_of(stop.group, stop.object - 1);
  return moqctl_loc_of(stop.group - 1, MOQCACHE_OBJ_ID_MAX);
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
    it->next       = moqctl_loc_of(cur.group, cur.object + 1);
    return;
  }
  it->unknown = 1;
  it->next    = moqcache_unknown_stop(c, off, cur, end);
  it->loc     = moqcache_prev(it->next);
}
