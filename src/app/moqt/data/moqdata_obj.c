#include "app/moqt/data/moqdata_impl.h"

static int moqdata_id_overflow(int have_prev, u64 prev_id, u64 delta);
static u64 moqdata_next_id(int have_prev, u64 prev_id, u64 delta);
static int moqdata_obj_take_id(
    wired_span buf, usz* at, const moqdata_objseq* seq, moqdata_obj* o);
static int moqdata_obj_skip(wired_span buf, usz* at, u64 n);
static int moqdata_obj_take_props_field(
    wired_span buf, usz* at, u64* props_len);
static int moqdata_obj_take_props(
    wired_span buf, usz* at, int has_props, u64* props_len);
static int moqdata_status_known(u64 s);
static int moqdata_obj_props_ok(u64 props_len, u64 status);
static int moqdata_obj_take_status(wired_span buf, usz* at, u64* status);
static int moqdata_obj_take_empty(
    wired_span buf, usz* at, u64 props_len, moqdata_obj* o);
static int moqdata_obj_take_payload(
    wired_span buf, usz* at, u64 len, moqdata_obj* o);
static int moqdata_obj_take_len(
    wired_span buf, usz* at, u64 props_len, moqdata_obj* o, u64* len);
static int moqdata_obj_head(
    wired_span            buf,
    usz*                  at,
    const moqdata_objseq* seq,
    moqdata_obj*          out,
    u64*                  len);
static int moqdata_obj_take_rest(
    wired_span buf, usz* at, u64 len, moqdata_obj* o);

static int moqdata_id_overflow(int have_prev, u64 prev_id, u64 delta) {
  if (!have_prev) {
    return 0;
  }
  return prev_id >= (u64)-1 - delta;
}

static u64 moqdata_next_id(int have_prev, u64 prev_id, u64 delta) {
  if (!have_prev) {
    return delta;
  }
  return prev_id + delta + 1;
}

static int moqdata_obj_take_id(
    wired_span buf, usz* at, const moqdata_objseq* seq, moqdata_obj* o) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (moqdata_id_overflow(seq->have_prev, seq->prev_id, delta)) {
    return MOQDATA_VIOLATION;
  }
  o->object_id = moqdata_next_id(seq->have_prev, seq->prev_id, delta);
  return MOQDATA_OK;
}

/* Bounds are checked by subtraction (never *at + n, which wraps for a
 * 64-bit wire length and rewinds the cursor); *at <= buf.n holds because
 * every cursor here was advanced only by successful takes. */
static int moqdata_obj_skip(wired_span buf, usz* at, u64 n) {
  if (n > buf.n - *at) {
    return 0;
  }
  *at += n;
  return 1;
}

static int moqdata_obj_take_props_field(
    wired_span buf, usz* at, u64* props_len) {
  if (!moqvi_take(buf, at, props_len)) {
    return 0;
  }
  return moqdata_obj_skip(buf, at, *props_len);
}

static int moqdata_obj_take_props(
    wired_span buf, usz* at, int has_props, u64* props_len) {
  *props_len = 0;
  if (!has_props) {
    return 1;
  }
  return moqdata_obj_take_props_field(buf, at, props_len);
}

static int moqdata_status_known(u64 s) {
  return s == MOQDATA_STATUS_NORMAL || s == MOQDATA_STATUS_END_OF_GROUP ||
         s == MOQDATA_STATUS_END_OF_TRACK;
}

static int moqdata_obj_props_ok(u64 props_len, u64 status) {
  return props_len == 0 || status == MOQDATA_STATUS_NORMAL;
}

static int moqdata_obj_take_status(wired_span buf, usz* at, u64* status) {
  if (!moqvi_take(buf, at, status)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (!moqdata_status_known(*status)) {
    return MOQDATA_VIOLATION;
  }
  return MOQDATA_OK;
}

static int moqdata_obj_take_empty(
    wired_span buf, usz* at, u64 props_len, moqdata_obj* o) {
  int r = moqdata_obj_take_status(buf, at, &o->status);
  if (r != MOQDATA_OK) {
    return r;
  }
  if (!moqdata_obj_props_ok(props_len, o->status)) {
    return MOQDATA_VIOLATION;
  }
  o->payload = wired_span_of(0, 0);
  return MOQDATA_OK;
}

static int moqdata_obj_take_payload(
    wired_span buf, usz* at, u64 len, moqdata_obj* o) {
  if (len > buf.n - *at) {
    return MOQDATA_INSUFFICIENT;
  }
  o->payload = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  o->status = MOQDATA_STATUS_NORMAL;
  return MOQDATA_OK;
}

/* Payload Length, and the Status a length-0 Object carries instead of a
 * payload: the header's last fields. A Normal Object's payload is left to
 * moqdata_obj_take_rest. */
static int moqdata_obj_take_len(
    wired_span buf, usz* at, u64 props_len, moqdata_obj* o, u64* len) {
  if (!moqvi_take(buf, at, len)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (*len == 0) {
    return moqdata_obj_take_empty(buf, at, props_len, o);
  }
  o->status = MOQDATA_STATUS_NORMAL;
  return MOQDATA_OK;
}

/* Every field of the Object at *at but its payload bytes; *len its
 * Payload Length. seq is read, not advanced. */
static int moqdata_obj_head(
    wired_span            buf,
    usz*                  at,
    const moqdata_objseq* seq,
    moqdata_obj*          out,
    u64*                  len) {
  u64 props_len;
  int r = moqdata_obj_take_id(buf, at, seq, out);
  if (r != MOQDATA_OK) {
    return r;
  }
  if (!moqdata_obj_take_props(buf, at, seq->has_props, &props_len)) {
    return MOQDATA_INSUFFICIENT;
  }
  out->props = wired_span_of(buf.p + *at - props_len, (usz)props_len);
  return moqdata_obj_take_len(buf, at, props_len, out, len);
}

/* The payload a non-zero Payload Length announced. */
static int moqdata_obj_take_rest(
    wired_span buf, usz* at, u64 len, moqdata_obj* o) {
  return len ? moqdata_obj_take_payload(buf, at, len, o) : MOQDATA_OK;
}

int moqdata_obj_take(
    wired_span buf, usz* off, moqdata_objseq* seq, moqdata_obj* out) {
  usz at = *off;
  u64 len;
  int r = moqdata_obj_head(buf, &at, seq, out, &len);
  if (r == MOQDATA_OK) {
    r = moqdata_obj_take_rest(buf, &at, len, out);
  }
  if (r != MOQDATA_OK) {
    return r;
  }
  seq->have_prev = 1;
  seq->prev_id   = out->object_id;
  *off           = at;
  return MOQDATA_OK;
}

int moqdata_obj_head_take(
    wired_span buf, usz off, moqdata_objseq seq, moqdata_obj* out) {
  u64 len;
  out->payload = wired_span_of(0, 0);
  return moqdata_obj_head(buf, &off, &seq, out, &len);
}
