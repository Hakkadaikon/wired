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
