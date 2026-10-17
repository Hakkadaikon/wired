#include "app/moqt/cache/moqcache_impl.h"

static moqctl_loc moqcache_rec_first(moqcache_rec r);
static moqctl_loc moqcache_rec_last(moqcache_rec r);
static int        moqcache_at_or_after(moqcache_rec r, u64 tag, moqctl_loc cur);
static usz moqcache_scan(const moqcache* c, usz off, u64 tag, moqctl_loc cur);
static int moqcache_resumes(const moqcache* c, u64 tag, moqctl_loc cur);
static int moqcache_covered(const moqcache* c, u64 tag, moqctl_loc cur);
static int moqcache_holds(const moqcache* c, usz off, moqctl_loc cur);
static moqctl_loc moqcache_gap_end(const moqcache* c, usz off, moqctl_loc end);

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

/* Offset of tag's first record from off reaching cur, else c->used. */
static usz moqcache_scan(const moqcache* c, usz off, u64 tag, moqctl_loc cur) {
  while (off < c->used &&
         !moqcache_at_or_after(moqcache_rec_at(c, off), tag, cur)) {
    off += moqcache_rec_size(moqcache_rec_at(c, off));
  }
  return off;
}

/* Every record of tag before the resume point ends before hint_cur, so
 * it ends before any cur not below hint_cur either. */
static int moqcache_resumes(const moqcache* c, u64 tag, moqctl_loc cur) {
  return c->hint_tag == tag && !moqctl_loc_less(cur, c->hint_cur);
}

/* Offset of tag's first record reaching cur, else c->used: scanned from
 * the resume point when it applies, which then moves here. */
usz moqcache_find(moqcache* c, u64 tag, moqctl_loc cur) {
  usz from    = moqcache_resumes(c, tag, cur) ? c->hint_off : 0;
  c->hint_off = moqcache_scan(c, from, tag, cur);
  c->hint_tag = tag;
  c->hint_cur = cur;
  return c->hint_off;
}

/* cur's group is not older than tag's oldest cached group: every
 * Location there is either cached, tombstoned or nonexistent (groups are
 * cached whole and evicted oldest first). */
static int moqcache_covered(const moqcache* c, u64 tag, moqctl_loc cur) {
  usz off = moqcache_scan(c, 0, tag, moqctl_loc_of(0, 0));
  return off < c->used && moqcache_rec_at(c, off).group <= cur.group;
}

static int moqcache_holds(const moqcache* c, usz off, moqctl_loc cur) {
  return off < c->used &&
         !moqctl_loc_less(cur, moqcache_rec_first(moqcache_rec_at(c, off)));
}

/* Where a skipped (nonexistent) stretch ends. */
static moqctl_loc moqcache_gap_end(const moqcache* c, usz off, moqctl_loc end) {
  if (off == c->used) {
    return end;
  }
  return moqctl_loc_min(moqcache_rec_first(moqcache_rec_at(c, off)), end);
}

moqctl_loc moqcache_skip(moqcache* c, u64 tag, moqctl_loc cur, moqctl_loc end) {
  usz off = moqcache_find(c, tag, cur);
  if (moqcache_holds(c, off, cur) || !moqcache_covered(c, tag, cur)) {
    return cur;
  }
  return moqcache_gap_end(c, off, end);
}

int moqcache_is_obj(moqcache_rec r, moqctl_loc cur) {
  return !moqcache_dead(r) && r.group == cur.group && r.object == cur.object;
}

/* End (exclusive) of the unknown range at cur: a tombstone's group ends
 * at the next group, anything else at the next record's group. Never at
 * or before cur, so a cursor only moves forward (a cached group is never
 * partial, so this only guards that invariant). */
moqctl_loc moqcache_unknown_stop(
    const moqcache* c, usz off, moqctl_loc cur, moqctl_loc end) {
  moqctl_loc stop = end;
  if (off < c->used) {
    stop = moqctl_loc_of(
        moqcache_rec_at(c, off).group + moqcache_dead(moqcache_rec_at(c, off)),
        0);
  }
  if (!moqctl_loc_less(cur, stop)) {
    stop = moqctl_loc_of(cur.group, cur.object + 1);
  }
  return moqctl_loc_min(stop, end);
}
