#include "app/moqt/data/moqdata_impl.h"

static int moqdata_classify_fixed(u64 v);
static int moqdata_classify_kind(u64 v);
static int moqdata_type_bit4(u64 t);
static int moqdata_type_mode_ok(u64 t);
static int moqdata_subhdr_take_sgid(wired_span buf, usz* at, moqdata_subhdr* h);
static int moqdata_subhdr_take_prio(wired_span buf, usz* at, moqdata_subhdr* h);
static int moqdata_subhdr_take_ids(wired_span buf, usz* at, moqdata_subhdr* h);
static int moqdata_subhdr_take_body(
    wired_span buf, usz* at, moqdata_subhdr* h, usz* off);

/* draft-ietf-moq-transport-19 data-plane: stream classification (3.4),
 * SUBGROUP_HEADER and Object framing (11.4.2 / 4237-4362). */

/* ===== stream classification (3.4) ===== */

static const struct {
  u64 v;
  int kind;
} MOQDATA_FIXED_TYPES[] = {
    {MOQDATA_TYPE_SETUP, MOQDATA_STREAM_CONTROL},
    {MOQDATA_TYPE_FETCH_HEADER, MOQDATA_STREAM_FETCH},
    {MOQDATA_TYPE_PADDING, MOQDATA_STREAM_PADDING},
};

static int moqdata_classify_fixed(u64 v) {
  for (usz i = 0; i < MOQDATA_FIXED_TYPES_N; i++) {
    if (MOQDATA_FIXED_TYPES[i].v == v) {
      return MOQDATA_FIXED_TYPES[i].kind;
    }
  }
  return 0;
}

static int moqdata_classify_kind(u64 v) {
  int fixed = moqdata_classify_fixed(v);
  if (fixed) {
    return fixed;
  }
  if (moqdata_type_valid(v)) {
    return MOQDATA_STREAM_SUBGROUP;
  }
  return MOQDATA_STREAM_UNKNOWN;
}

int moqdata_classify(wired_span in, usz* off) {
  usz at = 0;
  u64 v;
  if (!moqvi_take(in, &at, &v)) {
    return MOQDATA_STREAM_INSUFFICIENT;
  }
  *off = at;
  return moqdata_classify_kind(v);
}

/* ===== SUBGROUP_HEADER Type bits (11.4.2) ===== */

static int moqdata_type_bit4(u64 t) { return (t & 0x10) != 0; }

static int moqdata_type_mode_ok(u64 t) {
  return moqdata_type_sgid_mode(t) != 3;
}

int moqdata_type_valid(u64 type) {
  if (type & 0x80) {
    return 0;
  }
  if (!moqdata_type_bit4(type)) {
    return 0;
  }
  return moqdata_type_mode_ok(type);
}

int moqdata_type_props(u64 type) { return (type & 0x01) != 0; }

u64 moqdata_type_sgid_mode(u64 type) { return (type >> 1) & 0x3; }

int moqdata_type_end_of_group(u64 type) { return (type & 0x08) != 0; }

int moqdata_type_default_priority(u64 type) { return (type & 0x20) != 0; }

int moqdata_type_first_object(u64 type) { return (type & 0x40) != 0; }

/* ===== SUBGROUP_HEADER take/put (11.4.2) ===== */

static int moqdata_subhdr_take_sgid(
    wired_span buf, usz* at, moqdata_subhdr* h) {
  u64 mode = moqdata_type_sgid_mode(h->type);
  if (mode == 1) {
    h->subgroup_id_pending = 1;
    return 1;
  }
  if (mode != 2) {
    return 1;
  }
  return moqvi_take(buf, at, &h->subgroup_id);
}

static int moqdata_subhdr_take_prio(
    wired_span buf, usz* at, moqdata_subhdr* h) {
  if (moqdata_type_default_priority(h->type)) {
    h->priority = 0;
    return 1;
  }
  if (*at >= buf.n) {
    return 0;
  }
  h->priority = buf.p[*at];
  (*at)++;
  return 1;
}

static int moqdata_subhdr_take_ids(wired_span buf, usz* at, moqdata_subhdr* h) {
  if (!moqvi_take(buf, at, &h->track_alias)) {
    return 0;
  }
  if (!moqvi_take(buf, at, &h->group_id)) {
    return 0;
  }
  return moqdata_subhdr_take_sgid(buf, at, h);
}

static int moqdata_subhdr_take_body(
    wired_span buf, usz* at, moqdata_subhdr* h, usz* off) {
  if (!moqdata_subhdr_take_ids(buf, at, h)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (!moqdata_subhdr_take_prio(buf, at, h)) {
    return MOQDATA_INSUFFICIENT;
  }
  *off = *at;
  return MOQDATA_OK;
}

int moqdata_subhdr_take(wired_span buf, usz* off, moqdata_subhdr* h) {
  usz at = *off;
  u64 type;
  if (!moqvi_take(buf, &at, &type)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (!moqdata_type_valid(type)) {
    return MOQDATA_VIOLATION;
  }
  *h      = (moqdata_subhdr){0};
  h->type = type;
  return moqdata_subhdr_take_body(buf, &at, h, off);
}

void moqdata_subhdr_resolve(moqdata_subhdr* h, u64 first_object_id) {
  if (!h->subgroup_id_pending) {
    return;
  }
  h->subgroup_id         = first_object_id;
  h->subgroup_id_pending = 0;
}
