#include "app/moqt/cache/moqcache_impl.h"

static int moqcache_gone_live(
    const moqcache* c, const moqcache_gone* g, u64 tag);
static int moqcache_gone_into(
    const moqcache_gone* g, moqctl_loc cur, moqctl_loc* next);
static int moqcache_gone_cut(
    const moqcache*      c,
    const moqcache_gone* g,
    u64                  tag,
    moqctl_loc           cur,
    moqctl_loc*          next);
static int moqcache_gone_at(
    const moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc* next);
static moqctl_loc moqcache_gone_end(moqctl_loc last);

void moqcache_item_at(
    moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc end, moqcache_item* it) {
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
  it->gone    = moqcache_gone_at(c, tag, cur, &it->next);
  it->loc     = moqctl_loc_prev(it->next);
}

/* ----- Gone ranges (draft-23 7.1, 10.3) ----- */

/* g is tag's and not expired: 10.3 "The same limit applies to cached
 * Does Not Exist and Gone states", after which it is Unknown (2.1.2). */
static int moqcache_gone_live(
    const moqcache* c, const moqcache_gone* g, u64 tag) {
  return g->tag == tag && c->now < g->exp;
}

/* cur (not below g's start) lies in g: the range ends by g's end. */
static int moqcache_gone_into(
    const moqcache_gone* g, moqctl_loc cur, moqctl_loc* next) {
  if (!moqctl_loc_less(cur, g->hi)) {
    return 0;
  }
  *next = moqctl_loc_min(*next, g->hi);
  return 1;
}

/* The Unknown range at cur ending at *next, cut by g: Gone when cur lies
 * in it, else stopped where it starts ahead. */
static int moqcache_gone_cut(
    const moqcache*      c,
    const moqcache_gone* g,
    u64                  tag,
    moqctl_loc           cur,
    moqctl_loc*          next) {
  if (!moqcache_gone_live(c, g, tag)) {
    return 0;
  }
  if (moqctl_loc_less(cur, g->lo)) {
    *next = moqctl_loc_min(*next, g->lo);
    return 0;
  }
  return moqcache_gone_into(g, cur, next);
}

/* 1 when the Unknown range at cur is Gone; *next cut by every range. */
static int moqcache_gone_at(
    const moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc* next) {
  int gone = 0;
  for (usz i = 0; i < MOQCACHE_GONE_MAX; i++) {
    gone |= moqcache_gone_cut(c, &c->gone[i], tag, cur, next);
  }
  return gone;
}

/* Just past last; past a Group's last possible Object, the next Group. */
static moqctl_loc moqcache_gone_end(moqctl_loc last) {
  return last.object >= MOQCACHE_OBJ_ID_MAX
             ? moqctl_loc_of(last.group + 1, 0)
             : moqctl_loc_of(last.group, last.object + 1);
}

void moqcache_gone_add(
    moqcache* c, u64 tag, moqctl_loc lo, moqctl_loc last, u64 exp) {
  moqcache_gone* g;
  if (!c->cap) {
    return;
  }
  g      = &c->gone[c->gone_at++ % MOQCACHE_GONE_MAX];
  g->tag = tag;
  g->lo  = lo;
  g->hi  = moqcache_gone_end(last);
  g->exp = exp;
}
