#include "app/moqt/data/moqdata_impl.h"

static int moqdata_subhdr_put_sgid(
    wired_mspan buf, usz* at, const moqdata_subhdr* h);
static int moqdata_subhdr_put_prio(
    wired_mspan buf, usz* at, const moqdata_subhdr* h);
static int moqdata_subhdr_put_ids(
    wired_mspan buf, usz* at, const moqdata_subhdr* h);
static int moqdata_subhdr_put_body(
    wired_mspan buf, usz* at, const moqdata_subhdr* h);
static int moqdata_subhdr_put_rest(
    wired_mspan buf, usz* at, const moqdata_subhdr* h);

static int moqdata_subhdr_put_sgid(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  u64 mode = moqdata_type_sgid_mode(h->type);
  if (mode != 2) {
    return 1;
  }
  return moqvi_put(buf, at, h->subgroup_id);
}

static int moqdata_subhdr_put_prio(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (moqdata_type_default_priority(h->type)) {
    return 1;
  }
  if (*at >= buf.n) {
    return 0;
  }
  buf.p[*at] = (u8)h->priority;
  (*at)++;
  return 1;
}

static int moqdata_subhdr_put_ids(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (!moqvi_put(buf, at, h->track_alias)) {
    return 0;
  }
  if (!moqvi_put(buf, at, h->group_id)) {
    return 0;
  }
  return moqdata_subhdr_put_sgid(buf, at, h);
}

static int moqdata_subhdr_put_body(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (!moqdata_subhdr_put_ids(buf, at, h)) {
    return 0;
  }
  return moqdata_subhdr_put_prio(buf, at, h);
}

static int moqdata_subhdr_put_rest(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (!moqvi_put(buf, at, h->type)) {
    return 0;
  }
  return moqdata_subhdr_put_body(buf, at, h);
}

int moqdata_subhdr_put(wired_mspan buf, usz* off, const moqdata_subhdr* h) {
  usz at = *off;
  if (!moqdata_type_valid(h->type)) {
    return MOQDATA_VIOLATION;
  }
  if (!moqdata_subhdr_put_rest(buf, &at, h)) {
    return MOQDATA_INSUFFICIENT;
  }
  *off = at;
  return MOQDATA_OK;
}

/* ===== Object framing (4237-4362) ===== */

moqdata_objseq moqdata_objseq_of(u64 type) {
  moqdata_objseq s = {0};
  s.has_props      = moqdata_type_props(type);
  return s;
}
