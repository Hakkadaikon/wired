#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_rngf_put_prop(
    wired_mspan buf, usz* at, u64 ptype, const moqctl_rangefilter* f);
static int moqctl_rngf_put_head(
    wired_mspan buf, usz* at, u64 ptype, const moqctl_rangefilter* f);
static int moqctl_rngf_put_end(
    wired_mspan buf, usz* at, const moqctl_range* r, u64* prev_end);
static int moqctl_rngf_put_range(
    wired_mspan buf, usz* at, const moqctl_range* r, u64* prev_end);
static int moqctl_rngf_put_ranges(
    wired_mspan buf, usz* at, const moqctl_rangefilter* f);
static int moqctl_rngf_put_body(
    wired_mspan buf, usz* at, u64 ptype, const moqctl_rangefilter* f);

static int moqctl_rngf_put_prop(
    wired_mspan buf, usz* at, u64 ptype, const moqctl_rangefilter* f) {
  if (!moqctl_rngf_has_prop(ptype)) return 1;
  return moqvi_put(buf, at, f->prop_type);
}

static int moqctl_rngf_put_head(
    wired_mspan buf, usz* at, u64 ptype, const moqctl_rangefilter* f) {
  if (*at >= buf.n) return 0;
  buf.p[(*at)++] = (u8)f->set_id;
  return moqctl_rngf_put_prop(buf, at, ptype, f);
}

static int moqctl_rngf_put_end(
    wired_mspan buf, usz* at, const moqctl_range* r, u64* prev_end) {
  *prev_end = r->start;
  if (!r->has_end) return 1;
  *prev_end = r->end;
  return moqvi_put(buf, at, r->end - r->start);
}

static int moqctl_rngf_put_range(
    wired_mspan buf, usz* at, const moqctl_range* r, u64* prev_end) {
  if (!moqvi_put(buf, at, r->start - *prev_end)) return 0;
  return moqctl_rngf_put_end(buf, at, r, prev_end);
}

static int moqctl_rngf_put_ranges(
    wired_mspan buf, usz* at, const moqctl_rangefilter* f) {
  u64 prev_end = 0;
  for (usz i = 0; i < f->n; i++)
    if (!moqctl_rngf_put_range(buf, at, &f->r[i], &prev_end)) return 0;
  return 1;
}

static int moqctl_rngf_put_body(
    wired_mspan buf, usz* at, u64 ptype, const moqctl_rangefilter* f) {
  return moqctl_rngf_put_head(buf, at, ptype, f) &&
         moqctl_rngf_put_ranges(buf, at, f);
}

int moqctl_rangefilter_put(
    wired_mspan buf, usz* off, u64 ptype, const moqctl_rangefilter* f) {
  usz at = *off;
  if (f->remove) return 1; /* zero-length value */
  if (!moqctl_rngf_put_body(buf, &at, ptype, f)) return 0;
  *off = at;
  return 1;
}
