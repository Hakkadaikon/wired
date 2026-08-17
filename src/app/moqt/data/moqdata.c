#include "app/moqt/data/moqdata.h"

#include "app/moqt/vi/moqvi.h"

/* draft-ietf-moq-transport-19 data-plane: stream classification (3.4),
 * SUBGROUP_HEADER and Object framing (11.4.2 / 4237-4362). */

/* ===== stream classification (3.4) ===== */

static const struct {
  u64 v;
  int kind;
} MOQDATA_FIXED_TYPES[] = {
    {QUIC_MOQDATA_TYPE_SETUP, QUIC_MOQDATA_STREAM_CONTROL},
    {QUIC_MOQDATA_TYPE_FETCH_HEADER, QUIC_MOQDATA_STREAM_FETCH},
    {QUIC_MOQDATA_TYPE_PADDING, QUIC_MOQDATA_STREAM_PADDING},
};
#define MOQDATA_FIXED_TYPES_N \
  (sizeof MOQDATA_FIXED_TYPES / sizeof MOQDATA_FIXED_TYPES[0])

static int moqdata_classify_fixed(u64 v) {
  for (usz i = 0; i < MOQDATA_FIXED_TYPES_N; i++)
    if (MOQDATA_FIXED_TYPES[i].v == v) return MOQDATA_FIXED_TYPES[i].kind;
  return 0;
}

static int moqdata_classify_kind(u64 v) {
  int fixed = moqdata_classify_fixed(v);
  if (fixed) return fixed;
  if (moqdata_type_valid(v)) return QUIC_MOQDATA_STREAM_SUBGROUP;
  return QUIC_MOQDATA_STREAM_UNKNOWN;
}

int moqdata_classify(wired_span in, usz* off) {
  usz at = 0;
  u64 v;
  if (!moqvi_take(in, &at, &v)) return QUIC_MOQDATA_STREAM_INSUFFICIENT;
  *off = at;
  return moqdata_classify_kind(v);
}

/* ===== SUBGROUP_HEADER Type bits (11.4.2) ===== */

static int moqdata_type_bit4(u64 t) { return (t & 0x10) != 0; }

static int moqdata_type_mode_ok(u64 t) {
  return moqdata_type_sgid_mode(t) != 3;
}

int moqdata_type_valid(u64 type) {
  if (type & 0x80) return 0;
  if (!moqdata_type_bit4(type)) return 0;
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
  if (mode != 2) return 1;
  return moqvi_take(buf, at, &h->subgroup_id);
}

static int moqdata_subhdr_take_prio(
    wired_span buf, usz* at, moqdata_subhdr* h) {
  if (moqdata_type_default_priority(h->type)) {
    h->priority = 0;
    return 1;
  }
  if (*at >= buf.n) return 0;
  h->priority = buf.p[*at];
  (*at)++;
  return 1;
}

static int moqdata_subhdr_take_ids(wired_span buf, usz* at, moqdata_subhdr* h) {
  if (!moqvi_take(buf, at, &h->track_alias)) return 0;
  if (!moqvi_take(buf, at, &h->group_id)) return 0;
  return moqdata_subhdr_take_sgid(buf, at, h);
}

static int moqdata_subhdr_take_body(
    wired_span buf, usz* at, moqdata_subhdr* h, usz* off) {
  if (!moqdata_subhdr_take_ids(buf, at, h)) return QUIC_MOQDATA_INSUFFICIENT;
  if (!moqdata_subhdr_take_prio(buf, at, h)) return QUIC_MOQDATA_INSUFFICIENT;
  *off = *at;
  return QUIC_MOQDATA_OK;
}

int moqdata_subhdr_take(wired_span buf, usz* off, moqdata_subhdr* h) {
  usz at = *off;
  u64 type;
  if (!moqvi_take(buf, &at, &type)) return QUIC_MOQDATA_INSUFFICIENT;
  if (!moqdata_type_valid(type)) return QUIC_MOQDATA_VIOLATION;
  *h      = (moqdata_subhdr){0};
  h->type = type;
  return moqdata_subhdr_take_body(buf, &at, h, off);
}

void moqdata_subhdr_resolve(moqdata_subhdr* h, u64 first_object_id) {
  if (!h->subgroup_id_pending) return;
  h->subgroup_id         = first_object_id;
  h->subgroup_id_pending = 0;
}

static int moqdata_subhdr_put_sgid(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  u64 mode = moqdata_type_sgid_mode(h->type);
  if (mode != 2) return 1;
  return moqvi_put(buf, at, h->subgroup_id);
}

static int moqdata_subhdr_put_prio(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (moqdata_type_default_priority(h->type)) return 1;
  if (*at >= buf.n) return 0;
  buf.p[*at] = (u8)h->priority;
  (*at)++;
  return 1;
}

static int moqdata_subhdr_put_ids(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (!moqvi_put(buf, at, h->track_alias)) return 0;
  if (!moqvi_put(buf, at, h->group_id)) return 0;
  return moqdata_subhdr_put_sgid(buf, at, h);
}

static int moqdata_subhdr_put_body(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (!moqdata_subhdr_put_ids(buf, at, h)) return 0;
  return moqdata_subhdr_put_prio(buf, at, h);
}

static int moqdata_subhdr_put_rest(
    wired_mspan buf, usz* at, const moqdata_subhdr* h) {
  if (!moqvi_put(buf, at, h->type)) return 0;
  return moqdata_subhdr_put_body(buf, at, h);
}

int moqdata_subhdr_put(wired_mspan buf, usz* off, const moqdata_subhdr* h) {
  usz at = *off;
  if (!moqdata_type_valid(h->type)) return QUIC_MOQDATA_VIOLATION;
  if (!moqdata_subhdr_put_rest(buf, &at, h)) return QUIC_MOQDATA_INSUFFICIENT;
  *off = at;
  return QUIC_MOQDATA_OK;
}

/* ===== Object framing (4237-4362) ===== */

moqdata_objseq moqdata_objseq_of(u64 type) {
  moqdata_objseq s = {0};
  s.has_props      = moqdata_type_props(type);
  return s;
}

static int moqdata_id_overflow(int have_prev, u64 prev_id, u64 delta) {
  if (!have_prev) return 0;
  return prev_id >= (u64)-1 - delta;
}

static u64 moqdata_next_id(int have_prev, u64 prev_id, u64 delta) {
  if (!have_prev) return delta;
  return prev_id + delta + 1;
}

static int moqdata_obj_take_id(
    wired_span buf, usz* at, moqdata_objseq* seq, moqdata_obj* o) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return QUIC_MOQDATA_INSUFFICIENT;
  if (moqdata_id_overflow(seq->have_prev, seq->prev_id, delta))
    return QUIC_MOQDATA_VIOLATION;
  o->object_id = moqdata_next_id(seq->have_prev, seq->prev_id, delta);
  return QUIC_MOQDATA_OK;
}

static int moqdata_obj_skip(wired_span buf, usz* at, u64 n) {
  if (*at + n > buf.n) return 0;
  *at += n;
  return 1;
}

static int moqdata_obj_take_props_field(
    wired_span buf, usz* at, u64* props_len) {
  if (!moqvi_take(buf, at, props_len)) return 0;
  return moqdata_obj_skip(buf, at, *props_len);
}

static int moqdata_obj_take_props(
    wired_span buf, usz* at, int has_props, u64* props_len) {
  *props_len = 0;
  if (!has_props) return 1;
  return moqdata_obj_take_props_field(buf, at, props_len);
}

static int moqdata_status_known(u64 s) {
  return s == QUIC_MOQDATA_STATUS_NORMAL ||
         s == QUIC_MOQDATA_STATUS_END_OF_GROUP ||
         s == QUIC_MOQDATA_STATUS_END_OF_TRACK;
}

static int moqdata_obj_props_ok(u64 props_len, u64 status) {
  return props_len == 0 || status == QUIC_MOQDATA_STATUS_NORMAL;
}

static int moqdata_obj_take_status(wired_span buf, usz* at, u64* status) {
  if (!moqvi_take(buf, at, status)) return QUIC_MOQDATA_INSUFFICIENT;
  if (!moqdata_status_known(*status)) return QUIC_MOQDATA_VIOLATION;
  return QUIC_MOQDATA_OK;
}

static int moqdata_obj_take_empty(
    wired_span buf, usz* at, u64 props_len, moqdata_obj* o) {
  int r = moqdata_obj_take_status(buf, at, &o->status);
  if (r != QUIC_MOQDATA_OK) return r;
  if (!moqdata_obj_props_ok(props_len, o->status))
    return QUIC_MOQDATA_VIOLATION;
  o->payload = wired_span_of(0, 0);
  return QUIC_MOQDATA_OK;
}

static int moqdata_obj_take_payload(
    wired_span buf, usz* at, u64 len, moqdata_obj* o) {
  if (*at + len > buf.n) return QUIC_MOQDATA_INSUFFICIENT;
  o->payload = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  o->status = QUIC_MOQDATA_STATUS_NORMAL;
  return QUIC_MOQDATA_OK;
}

static int moqdata_obj_take_body(
    wired_span buf, usz* at, u64 props_len, moqdata_obj* o) {
  u64 len;
  if (!moqvi_take(buf, at, &len)) return QUIC_MOQDATA_INSUFFICIENT;
  if (len == 0) return moqdata_obj_take_empty(buf, at, props_len, o);
  return moqdata_obj_take_payload(buf, at, len, o);
}

static int moqdata_obj_take_finish(
    wired_span      buf,
    usz*            at,
    u64             props_len,
    moqdata_objseq* seq,
    moqdata_obj*    out,
    usz*            off) {
  int r = moqdata_obj_take_body(buf, at, props_len, out);
  if (r != QUIC_MOQDATA_OK) return r;
  seq->have_prev = 1;
  seq->prev_id   = out->object_id;
  *off           = *at;
  return QUIC_MOQDATA_OK;
}

int moqdata_obj_take(
    wired_span buf, usz* off, moqdata_objseq* seq, moqdata_obj* out) {
  usz at = *off;
  u64 props_len;
  int r = moqdata_obj_take_id(buf, &at, seq, out);
  if (r != QUIC_MOQDATA_OK) return r;
  if (!moqdata_obj_take_props(buf, &at, seq->has_props, &props_len))
    return QUIC_MOQDATA_INSUFFICIENT;
  return moqdata_obj_take_finish(buf, &at, props_len, seq, out, off);
}

static int moqdata_span_copy(wired_mspan buf, usz* at, wired_span payload) {
  if (*at + payload.n > buf.n) return 0;
  for (usz i = 0; i < payload.n; i++) buf.p[*at + i] = payload.p[i];
  *at += payload.n;
  return 1;
}

static int moqdata_obj_put_body(wired_mspan buf, usz* at, wired_span payload) {
  if (!moqvi_put(buf, at, payload.n)) return 0;
  if (payload.n == 0) return moqvi_put(buf, at, QUIC_MOQDATA_STATUS_NORMAL);
  return moqdata_span_copy(buf, at, payload);
}

int moqdata_obj_put(
    wired_mspan buf, usz* off, u64 id_delta, wired_span payload) {
  usz at = *off;
  if (!moqvi_put(buf, &at, id_delta)) return QUIC_MOQDATA_INSUFFICIENT;
  if (!moqdata_obj_put_body(buf, &at, payload))
    return QUIC_MOQDATA_INSUFFICIENT;
  *off = at;
  return QUIC_MOQDATA_OK;
}

static int moqdata_obj_put_status_body(wired_mspan buf, usz* at, u64 status) {
  if (!moqvi_put(buf, at, 0)) return 0;
  return moqvi_put(buf, at, status);
}

int moqdata_obj_put_status(
    wired_mspan buf, usz* off, u64 id_delta, u64 status) {
  usz at = *off;
  if (!moqvi_put(buf, &at, id_delta)) return QUIC_MOQDATA_INSUFFICIENT;
  if (!moqdata_obj_put_status_body(buf, &at, status))
    return QUIC_MOQDATA_INSUFFICIENT;
  *off = at;
  return QUIC_MOQDATA_OK;
}

/* ===== one-message builder ===== */

#define MOQDATA_MSG_TYPE                        \
  0x70ULL /* PROPERTIES off, mode 0b00, no eog, \
              default priority, FIRST_OBJECT set */

int moqdata_msg_build(wired_mspan buf, usz* off, const moqdata_msg* m) {
  usz            at = *off;
  moqdata_subhdr h  = {0};
  h.type            = MOQDATA_MSG_TYPE;
  h.track_alias     = m->track_alias;
  h.group_id        = m->group_id;
  if (moqdata_subhdr_put(buf, &at, &h) != QUIC_MOQDATA_OK)
    return QUIC_MOQDATA_INSUFFICIENT;
  if (moqdata_obj_put(buf, &at, 0, m->payload) != QUIC_MOQDATA_OK)
    return QUIC_MOQDATA_INSUFFICIENT;
  *off = at;
  return QUIC_MOQDATA_OK;
}
