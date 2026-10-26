#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_fsel_field(const moqtrun_fsel_obj* o, u64 ptype, u64* v);
static int moqtrun_fsel_prop(const moqtrun_fsel_obj* o, u64 type, u64* v);
static int moqtrun_fsel_val(
    const moqtrun_fsel_obj* o, const wired_moqtrun_rngrow* r, u64* v);
static int moqtrun_fsel_prop_eq(
    const wired_moqtrun_rngrow* a, const wired_moqtrun_rngrow* b);
static int moqtrun_fsel_same_dim(
    const wired_moqtrun_rngrow* a, const wired_moqtrun_rngrow* b);
static int moqtrun_fsel_dim(
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    const wired_moqtrun_rngrow* r,
    const moqtrun_fsel_obj*     o);
static int moqtrun_fsel_set(
    const wired_moqtrun_rngrow* rows, usz n, u8 set, const moqtrun_fsel_obj* o);
static int moqtrun_fsel_live(usz n, moqctl_loc cur, moqctl_loc end);
static int moqtrun_fsel_drop_at(
    moqcache*                   c,
    u64                         tag,
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    moqctl_loc                  cur,
    moqctl_loc                  end);

/* ===== Range Filters on a FETCH or fill response (draft-22 3.3.2) =====
 * "The publisher MUST forward only objects that pass all filters"
 * (3.3.3). A FETCH's (a fill's: its subscription's, 3.4) Range Filter
 * rows judge every Object it serves -- cached ones by Object ID alone
 * (the cache keeps no Subgroup ID, priority or Properties, so a set
 * naming those passes no cached Object), upstream ones by every field.
 * An Object left out is an unmarked gap, which a filtered response's
 * receiver reads as unknown, not as nonexistent (3.2.2). */

/* Subgroup ID, Object ID or Publisher Priority (0x25-0x27) of o. */
static int moqtrun_fsel_field(const moqtrun_fsel_obj* o, u64 ptype, u64* v) {
  u64 i = ptype - MOQCTL_PARAM_SUBGROUP_FILTER;
  if (i >= 3) {
    return 0;
  }
  *v = o->v[i];
  return (o->have >> i) & 1;
}

/* Object Property type's value (9.20.13: an Object without it fails). */
static int moqtrun_fsel_prop(const moqtrun_fsel_obj* o, u64 type, u64* v) {
  *v = moqtrun_tprop(o->props, type, 0);
  return o->has_props && (*v != 0 || moqtrun_tprop(o->props, type, 1) == 0);
}

/* The value r's filter tests, 0 when o does not have it. */
static int moqtrun_fsel_val(
    const moqtrun_fsel_obj* o, const wired_moqtrun_rngrow* r, u64* v) {
  if (r->ptype == MOQCTL_PARAM_OBJECT_PROPERTY_FILTER) {
    return moqtrun_fsel_prop(o, r->prop_type, v);
  }
  return moqtrun_fsel_field(o, r->ptype, v);
}

static int moqtrun_fsel_prop_eq(
    const wired_moqtrun_rngrow* a, const wired_moqtrun_rngrow* b) {
  return a->has_prop == b->has_prop &&
         a->prop_type * a->has_prop == b->prop_type * b->has_prop;
}

/* a and b are Ranges of one filter parameter: same SetID, Type and
 * Property Type (3.3.2: Ranges OR within it). */
static int moqtrun_fsel_same_dim(
    const wired_moqtrun_rngrow* a, const wired_moqtrun_rngrow* b) {
  return a->set_id == b->set_id && a->ptype == b->ptype &&
         moqtrun_fsel_prop_eq(a, b);
}

/* o passes r's filter parameter: some Range of it holds o's value. */
static int moqtrun_fsel_dim(
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    const wired_moqtrun_rngrow* r,
    const moqtrun_fsel_obj*     o) {
  u64 v;
  int hit = 0;
  if (!moqtrun_fsel_val(o, r, &v)) {
    return 0;
  }
  for (usz i = 0; i < n; i++) {
    hit |= moqtrun_fsel_same_dim(&rows[i], r) & moqtrun_row_in(&rows[i], v);
  }
  return hit;
}

/* o passes every filter parameter of SetID set (AND within a set). */
static int moqtrun_fsel_set(
    const wired_moqtrun_rngrow* rows,
    usz                         n,
    u8                          set,
    const moqtrun_fsel_obj*     o) {
  int ok = 1;
  for (usz i = 0; i < n; i++) {
    ok &= rows[i].set_id != set || moqtrun_fsel_dim(rows, n, &rows[i], o);
  }
  return ok;
}

/* o passes rows: no rows at all, or any SetID passes (sets OR). */
int moqtrun_fsel_pass(
    const wired_moqtrun_rngrow* rows, usz n, const moqtrun_fsel_obj* o) {
  int pass = n == 0;
  for (usz i = 0; i < n; i++) {
    pass |= moqtrun_fsel_set(rows, n, rows[i].set_id, o);
  }
  return pass;
}

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
