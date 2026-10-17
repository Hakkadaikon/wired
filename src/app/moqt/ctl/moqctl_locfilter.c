#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_locfilter_needs_start(u64 t);
static int moqctl_locfilter_take_end_value(
    wired_span buf, usz* at, moqctl_locfilter* out);
static int moqctl_locfilter_take_end(
    wired_span buf, usz* at, moqctl_locfilter* out);
static int moqctl_locfilter_take_start_then_end(
    wired_span buf, usz* at, moqctl_locfilter* out);
static int moqctl_locfilter_take_range(
    wired_span buf, usz* at, moqctl_locfilter* out);
static int moqctl_locfilter_take_type(
    wired_span buf, usz* at, moqctl_locfilter* out);
static int moqctl_locfilter_put_end(
    wired_mspan buf, usz* at, const moqctl_locfilter* f);
static int moqctl_locfilter_put_start_then_end(
    wired_mspan buf, usz* at, const moqctl_locfilter* f);
static int moqctl_locfilter_put_range(
    wired_mspan buf, usz* at, const moqctl_locfilter* f);

/* ===== Location Filter (SS9.3.1) ===== */

static const u64 MOQCTL_LOCFILTER_TYPES[] = {
    MOQCTL_FILTER_NEXT_GROUP, MOQCTL_FILTER_LARGEST, MOQCTL_FILTER_ABS_START,
    MOQCTL_FILTER_ABS_RANGE};

static int moqctl_locfilter_needs_start(u64 t) {
  return t == MOQCTL_FILTER_ABS_START || t == MOQCTL_FILTER_ABS_RANGE;
}

/* Reads End Group Delta and range-checks it; only called once type ==
 * ABS_RANGE and Start is already filled in. */
static int moqctl_locfilter_take_end_value(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (!moqvi_take(buf, at, &out->end_group_delta)) {
    return MOQCTL_INSUFFICIENT;
  }
  u64 end;
  return u64_add_ok(out->start.group, out->end_group_delta, &end)
             ? MOQCTL_OK
             : MOQCTL_VIOLATION;
}

static int moqctl_locfilter_take_end(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (out->type != MOQCTL_FILTER_ABS_RANGE) {
    return MOQCTL_OK;
  }
  return moqctl_locfilter_take_end_value(buf, at, out);
}

static int moqctl_locfilter_take_start_then_end(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (moqctl_loc_take(buf, at, &out->start) != MOQCTL_OK) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqctl_locfilter_take_end(buf, at, out);
}

static int moqctl_locfilter_take_range(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (!moqctl_locfilter_needs_start(out->type)) {
    return MOQCTL_OK;
  }
  return moqctl_locfilter_take_start_then_end(buf, at, out);
}

static int moqctl_locfilter_take_type(
    wired_span buf, usz* at, moqctl_locfilter* out) {
  if (!moqvi_take(buf, at, &out->type)) {
    return MOQCTL_INSUFFICIENT;
  }
  if (!moqctl_u64_in(
          MOQCTL_LOCFILTER_TYPES, MOQCTL_LOCFILTER_TYPES_N, out->type)) {
    return MOQCTL_VIOLATION;
  }
  return MOQCTL_OK;
}

int moqctl_locfilter_take(wired_span buf, usz* off, moqctl_locfilter* out) {
  usz at = *off;
  int r;
  *out = (moqctl_locfilter){0};
  r    = moqctl_locfilter_take_type(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  r = moqctl_locfilter_take_range(buf, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_locfilter_put_end(
    wired_mspan buf, usz* at, const moqctl_locfilter* f) {
  if (f->type != MOQCTL_FILTER_ABS_RANGE) {
    return 1;
  }
  return moqvi_put(buf, at, f->end_group_delta);
}

static int moqctl_locfilter_put_start_then_end(
    wired_mspan buf, usz* at, const moqctl_locfilter* f) {
  if (!moqctl_loc_put(buf, at, f->start)) {
    return 0;
  }
  return moqctl_locfilter_put_end(buf, at, f);
}

static int moqctl_locfilter_put_range(
    wired_mspan buf, usz* at, const moqctl_locfilter* f) {
  if (!moqctl_locfilter_needs_start(f->type)) {
    return 1;
  }
  return moqctl_locfilter_put_start_then_end(buf, at, f);
}

int moqctl_locfilter_put(wired_mspan buf, usz* off, const moqctl_locfilter* f) {
  usz at = *off;
  if (!moqvi_put(buf, &at, f->type)) {
    return 0;
  }
  if (!moqctl_locfilter_put_range(buf, &at, f)) {
    return 0;
  }
  *off = at;
  return 1;
}
