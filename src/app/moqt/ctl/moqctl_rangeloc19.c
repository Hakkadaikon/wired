#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_rangeloc19_next_group(moqctl_rangeloc* out);
static int moqctl_rangeloc19_abs_start(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc19_abs_range(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc19_next_group_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc19_largest_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc19_body(
    u64 type, wired_span buf, usz* at, moqctl_rangeloc* out);
static u64 moqctl_rangeloc19_wire_type_abs(const moqctl_rangeloc* r);

/* ===== Version-neutral range model (moqctl_rangeloc) ===== */

/* End Group Delta, resolved to an absolute end_group; overflow of
 * start_group+delta past 2^64-1 -> VIOLATION (shared by d19 type 4 and
 * d22 types 3/4). */
int moqctl_rangeloc_take_end_group(
    wired_span buf, usz* at, u64 start_group, u64* end_group) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return MOQCTL_INSUFFICIENT;
  return u64_add_ok(start_group, delta, end_group) ? MOQCTL_OK
                                                   : MOQCTL_VIOLATION;
}

/* ----- draft-19 (SS5.1.2/SS10.2.9): type 0x1..0x4 -----
 * One function per type, dispatched by a type-indexed table so no
 * function carries more than its own type's branches (CCN). */

static int moqctl_rangeloc19_next_group(moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_REL_GROUP; /* n = 0 */
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

int moqctl_rangeloc19_largest(moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_NEXT_OBJ;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

static int moqctl_rangeloc19_abs_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_ABS;
  out->ek = MOQCTL_REK_UNBOUNDED;
  if (!moqvi_take(buf, at, &out->start_group)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(buf, at, &out->start_object)) return MOQCTL_INSUFFICIENT;
  return MOQCTL_OK;
}

static int moqctl_rangeloc19_abs_range(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc19_abs_start(buf, at, out);
  if (r != MOQCTL_OK) return r;
  out->ek = MOQCTL_REK_GROUP;
  return moqctl_rangeloc_take_end_group(
      buf, at, out->start_group, &out->end_group);
}

static int moqctl_rangeloc19_next_group_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  (void)buf;
  (void)at;
  return moqctl_rangeloc19_next_group(out);
}

static int moqctl_rangeloc19_largest_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  (void)buf;
  (void)at;
  return moqctl_rangeloc19_largest(out);
}

/* Index 0 unused (type 0 is not a valid d19 Filter Type); indices 1..4
 * are MOQCTL_FILTER_NEXT_GROUP..MOQCTL_FILTER_ABS_RANGE. */
static const moqctl_rangeloc19_fn MOQCTL_RANGELOC19_FNS[5] = {
    0, moqctl_rangeloc19_next_group_fn, moqctl_rangeloc19_largest_fn,
    moqctl_rangeloc19_abs_start, moqctl_rangeloc19_abs_range};

static int moqctl_rangeloc19_body(
    u64 type, wired_span buf, usz* at, moqctl_rangeloc* out) {
  if (type == 0 || type >= MOQCTL_RANGELOC19_FNS_N) return MOQCTL_VIOLATION;
  return MOQCTL_RANGELOC19_FNS[type](buf, at, out);
}

int moqctl_rangeloc19_take(wired_span buf, usz* off, moqctl_rangeloc* out) {
  usz at = *off;
  u64 type;
  int r;
  *out = (moqctl_rangeloc){0};
  if (!moqvi_take(buf, &at, &type)) return MOQCTL_INSUFFICIENT;
  r = moqctl_rangeloc19_body(type, buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static u64 moqctl_rangeloc19_wire_type_abs(const moqctl_rangeloc* r) {
  return r->ek == MOQCTL_REK_GROUP ? MOQCTL_FILTER_ABS_RANGE
                                   : MOQCTL_FILTER_ABS_START;
}

u64 moqctl_rangeloc19_wire_type(const moqctl_rangeloc* r) {
  if (r->sk == MOQCTL_RSK_REL_GROUP) return MOQCTL_FILTER_NEXT_GROUP;
  if (r->sk == MOQCTL_RSK_NEXT_OBJ) return MOQCTL_FILTER_LARGEST;
  return moqctl_rangeloc19_wire_type_abs(r);
}
