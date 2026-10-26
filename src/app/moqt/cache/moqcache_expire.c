#include "app/moqt/cache/moqcache_impl.h"

static int moqcache_expired(const moqcache* c, moqcache_rec r);
static usz moqcache_expired_at(const moqcache* c);
static u64 moqcache_min_exp(const moqcache* c);

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
