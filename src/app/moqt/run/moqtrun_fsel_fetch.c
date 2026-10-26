#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_fsel_cached_pass(
    const wired_moqtrun_rngrow* rows, usz n, moqctl_loc l);
static int moqtrun_fsel_live(usz n, moqctl_loc cur, moqctl_loc end);
static int moqtrun_fsel_drop_at(
    moqcache*                   c,
    u64                         tag,
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    moqctl_loc                  cur,
    moqctl_loc                  end);

/* Range Filters applied to a FETCH's or fill's Objects (moqtrun_fsel.c's
 * judge, draft-22 3.3.2-3.3.3): the cache walk and upstream items. */

/* The cached Object at l as a filter sees it: its Object ID alone. */
static int moqtrun_fsel_cached_pass(
    const wired_moqtrun_rngrow* rows, usz n, moqctl_loc l) {
  moqtrun_fsel_obj o = {{0, l.object, 0}, {0, 0}, 2, 0};
  return moqtrun_fsel_pass(rows, n, &o);
}

/* Filtered, with cur still below end. */
static int moqtrun_fsel_live(usz n, moqctl_loc cur, moqctl_loc end) {
  return n && moqctl_loc_less(cur, end);
}

/* cur (below end) holds a cached Object rows leave out. */
static int moqtrun_fsel_drop_at(
    moqcache*                   c,
    u64                         tag,
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    moqctl_loc                  cur,
    moqctl_loc                  end) {
  moqcache_item it;
  if (!moqtrun_fsel_live(n, cur, end)) {
    return 0;
  }
  moqcache_item_at(c, tag, cur, end, &it);
  return !it.unknown && !moqtrun_fsel_cached_pass(rows, n, it.loc);
}

/* moqcache_skip, also past cached Objects rows leave out: the next
 * Location a filtered response serves from. */
moqctl_loc moqtrun_fsel_skip(
    moqcache*                   c,
    u64                         tag,
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    moqctl_loc                  from,
    moqctl_loc                  end) {
  moqctl_loc cur = moqcache_skip(c, tag, from, end);
  while (moqtrun_fsel_drop_at(c, tag, rows, n, cur, end)) {
    cur = moqcache_skip(c, tag, moqtrun_after(cur), end);
  }
  return cur;
}

/* moqtrun_fsel_skip over f's own rows and track. */
moqctl_loc moqtrun_fsel_fskip(
    moqcache*                  c,
    const wired_moqtrun_fetch* f,
    moqctl_loc                 from,
    moqctl_loc                 end) {
  return moqtrun_fsel_skip(c, f->cache_tag, f->rngf, f->rngf_n, from, end);
}

/* rows (n of them, at most WIRED_MOQTRUN_MAX_FILTER_RANGES) kept on f. */
void moqtrun_fsel_keep(
    wired_moqtrun_fetch* f, const wired_moqtrun_rngrow* rows, usz n) {
  bytes_memcpy(f->rngf, rows, n * sizeof rows[0]);
  f->rngf_n = (u8)n;
}

/* params' Range Filters (vetted against MAX_FILTER_RANGES at decode,
 * moqtrun_fetch_verdict) flattened into rows; their count. */
usz moqtrun_fsel_rows(const moqctl_params* params, wired_moqtrun_rngrow* rows) {
  u8 n = 0;
  for (usz i = 0; i < params->n; i++) {
    moqctl_rangefilter f;
    if (moqtrun_rngf_of(&params->items[i], &f)) {
      moqtrun_rngf_rows_add(rows, &n, params->items[i].type, &f);
    }
  }
  return n;
}

/* An upstream fetch Object as a filter sees it (11.4.4: every field). */
int moqtrun_fsel_up_pass(const wired_moqtrun_fetch* f, const moqfetch_obj* o) {
  moqtrun_fsel_obj s = {
      {o->subgroup, o->object, o->priority},
      o->props,
      (u8)(2 | 4 | (o->has_subgroup != 0)),
      (u8)1};
  return moqtrun_fsel_pass(f->rngf, f->rngf_n, &s);
}
