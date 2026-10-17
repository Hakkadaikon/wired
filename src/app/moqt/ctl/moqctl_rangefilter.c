#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_rngf_take_prop(
    u64 ptype, wired_span v, usz* at, moqctl_rangefilter* out);
static int moqctl_rngf_take_head(
    u64 ptype, wired_span v, usz* at, moqctl_rangefilter* out);
static int moqctl_rngf_start(moqctl_rangefilter* f, u64 prev_end, u64 delta);
static int moqctl_rngf_end_value(
    wired_span v, usz* at, moqctl_rangefilter* f, u64* prev_end);
static int moqctl_rngf_take_end(
    wired_span v, usz* at, moqctl_rangefilter* f, u64* prev_end);
static int moqctl_rngf_take_range(
    wired_span v, usz* at, moqctl_rangefilter* f, u64* prev_end);
static int moqctl_rngf_more(wired_span v, usz at, const moqctl_rangefilter* f);
static int moqctl_rngf_take_ranges(
    wired_span v, usz* at, moqctl_rangefilter* f);

static int moqctl_rngf_take_prop(
    u64 ptype, wired_span v, usz* at, moqctl_rangefilter* out) {
  if (!moqctl_rngf_has_prop(ptype)) {
    return MOQCTL_OK;
  }
  out->has_prop = 1;
  return moqvi_take(v, at, &out->prop_type) ? MOQCTL_OK : MOQCTL_PARAMS_KVFMT;
}

/* SetID is one byte (SS10.2.10), then the 0x28/0x29 Property Type. */
static int moqctl_rngf_take_head(
    u64 ptype, wired_span v, usz* at, moqctl_rangefilter* out) {
  if (*at >= v.n) {
    return MOQCTL_PARAMS_KVFMT;
  }
  out->set_id = v.p[(*at)++];
  return moqctl_rngf_take_prop(ptype, v, at, out);
}

/* 0 when the filter is already at capacity or the Start delta sums past
 * 2^64-1: invalid is set and parsing stops (INVALID_FILTER at the
 * message layer, SS10.2.10). */
static int moqctl_rngf_start(moqctl_rangefilter* f, u64 prev_end, u64 delta) {
  if (f->n >= MOQCTL_MAX_RANGES ||
      !u64_add_ok(prev_end, delta, &f->r[f->n].start)) {
    f->invalid = 1;
    return 0;
  }
  return 1;
}

static int moqctl_rngf_end_value(
    wired_span v, usz* at, moqctl_rangefilter* f, u64* prev_end) {
  u64           delta;
  moqctl_range* r = &f->r[f->n];
  if (!moqvi_take(v, at, &delta)) {
    return MOQCTL_PARAMS_KVFMT;
  }
  if (!u64_add_ok(r->start, delta, &r->end)) {
    f->invalid = 1;
  }
  r->has_end = 1;
  *prev_end  = r->end;
  f->n++;
  return MOQCTL_OK;
}

/* The final End may be omitted: that range is open-ended. */
static int moqctl_rngf_take_end(
    wired_span v, usz* at, moqctl_rangefilter* f, u64* prev_end) {
  moqctl_range* r = &f->r[f->n];
  if (*at == v.n) {
    r->has_end = 0;
    *prev_end  = r->start;
    f->n++;
    return MOQCTL_OK;
  }
  return moqctl_rngf_end_value(v, at, f, prev_end);
}

static int moqctl_rngf_take_range(
    wired_span v, usz* at, moqctl_rangefilter* f, u64* prev_end) {
  u64 delta;
  if (!moqvi_take(v, at, &delta)) {
    return MOQCTL_PARAMS_KVFMT;
  }
  if (!moqctl_rngf_start(f, *prev_end, delta)) {
    return MOQCTL_OK;
  }
  return moqctl_rngf_take_end(v, at, f, prev_end);
}

static int moqctl_rngf_more(wired_span v, usz at, const moqctl_rangefilter* f) {
  return at < v.n && !f->invalid;
}

static int moqctl_rngf_take_ranges(
    wired_span v, usz* at, moqctl_rangefilter* f) {
  u64 prev_end = 0;
  while (moqctl_rngf_more(v, *at, f)) {
    int r = moqctl_rngf_take_range(v, at, f, &prev_end);
    if (r != MOQCTL_OK) {
      return r;
    }
  }
  return MOQCTL_OK;
}

int moqctl_rangefilter_take(
    u64 ptype, wired_span value, moqctl_rangefilter* out) {
  usz at = 0;
  int r;
  *out = (moqctl_rangefilter){0};
  if (value.n == 0) {
    out->remove = 1;
    return MOQCTL_OK;
  }
  r = moqctl_rngf_take_head(ptype, value, &at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  return moqctl_rngf_take_ranges(value, &at, out);
}
