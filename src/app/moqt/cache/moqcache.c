#include "app/moqt/cache/moqcache_impl.h"

static int moqcache_later(moqcache_rec r, moqcache_rec v);
static int moqcache_open(const moqcache* c, moqcache_rec v);
static int moqcache_victim(
    const moqcache* c, moqcache_rec r, u64 tag, u64 group);

void moqcache_init(moqcache* c, u8* arena, usz cap) {
  c->arena    = arena;
  c->cap      = cap;
  c->used     = 0;
  c->hint_off = 0;
  c->hint_tag = 0;
  c->hint_cur = moqctl_loc_of(0, 0);
  c->now      = 0;
  c->next_exp = ~(u64)0;
}

moqcache_rec moqcache_rec_at(const moqcache* c, usz off) {
  moqcache_rec r;
  bytes_memcpy(&r, c->arena + off, sizeof r);
  return r;
}

int moqcache_dead(moqcache_rec r) { return r.len == MOQCACHE_DEAD; }

usz moqcache_rec_size(moqcache_rec r) {
  return MOQCACHE_HDR + (moqcache_dead(r) ? 0 : (usz)r.len);
}

/* r belongs to tag's group (any group when any). */
int moqcache_hit(moqcache_rec r, u64 tag, u64 group, int any) {
  return r.tag == tag && (any || r.group == group);
}

/* Removes the matching records, sliding the rest down. */
void moqcache_drop(moqcache* c, u64 tag, u64 group, int any) {
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
  c->used     = w;
  c->hint_off = 0; /* records moved */
}

void moqcache_release(moqcache* c, u64 tag) { moqcache_drop(c, tag, 0, 1); }

/* Appends r (+ len bytes at p); the caller made room. */
void moqcache_write(moqcache* c, moqcache_rec r, const u8* p, usz len) {
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
       off += moqcache_rec_size(moqcache_rec_at(c, off))) {
    if (moqcache_later(moqcache_rec_at(c, off), v)) {
      return 0;
    }
  }
  return 1;
}

/* v stays open once an Object of tag's group is stored: it is its
 * track's newest group and the arriving Object does not start a newer
 * group of that track. */
int moqcache_stays_open(const moqcache* c, moqcache_rec v, u64 tag, u64 group) {
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

usz moqcache_first_victim(const moqcache* c, u64 tag, u64 group) {
  usz off = 0;
  while (off < c->used &&
         !moqcache_victim(c, moqcache_rec_at(c, off), tag, group)) {
    off += moqcache_rec_size(moqcache_rec_at(c, off));
  }
  return off;
}

/* Replaces a cached group by its tombstone, in place of its bytes (a
 * group holds at least one record, so the tombstone always fits). */
void moqcache_entomb(moqcache* c, u64 tag, u64 group) {
  moqcache_rec t = {tag, group, 0, MOQCACHE_DEAD, ~(u64)0};
  moqcache_drop(c, tag, group, 0);
  moqcache_write(c, t, 0, 0);
}

static int moqcache_expired(const moqcache* c, moqcache_rec r) {
  return !moqcache_dead(r) && r.exp <= c->now;
}

/* Offset of the first record past its expiry, else c->used. */
static usz moqcache_expired_at(const moqcache* c) {
  usz off = 0;
  while (off < c->used && !moqcache_expired(c, moqcache_rec_at(c, off))) {
    off += moqcache_rec_size(moqcache_rec_at(c, off));
  }
  return off;
}

static u64 moqcache_min_exp(const moqcache* c) {
  u64 m = ~(u64)0;
  for (usz off = 0; off < c->used;
       off += moqcache_rec_size(moqcache_rec_at(c, off))) {
    m = u64_min(m, moqcache_rec_at(c, off).exp);
  }
  return m;
}

/* draft-18 12.3: "Once Objects have expired from cache, their state
 * becomes unknown" -- each group holding an expired record becomes a
 * tombstone (a group is never cached partially). */
void moqcache_expire(moqcache* c) {
  usz off;
  if (c->now < c->next_exp) {
    return;
  }
  for (off = moqcache_expired_at(c); off < c->used;
       off = moqcache_expired_at(c)) {
    moqcache_rec r = moqcache_rec_at(c, off);
    moqcache_entomb(c, r.tag, r.group);
  }
  c->next_exp = moqcache_min_exp(c);
}
