#include "app/moqt/cache/moqcache_impl.h"

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
  it->loc     = moqctl_loc_prev(it->next);
}
