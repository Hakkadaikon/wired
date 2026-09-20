#include "app/moqt/dgram/moqdg.h"

#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"

/* draft-ietf-moq-transport-19 11.3.1 OBJECT_DATAGRAM codec. */

/* ===== Type bits (11.3.1) ===== */

static int moqdg_type_props(u64 t) { return (t & 0x01) != 0; }
static int moqdg_type_zero_oid(u64 t) { return (t & 0x04) != 0; }
static int moqdg_type_default_prio(u64 t) { return (t & 0x08) != 0; }
static int moqdg_type_status(u64 t) { return (t & 0x20) != 0; }

/* 0b00X0XXXX: bits 7, 6 and 4 clear (0x00..0x0F, 0x20..0x2F). */
static int moqdg_type_form_ok(u64 t) { return (t & 0xD0) == 0; }

/* STATUS + END_OF_GROUP is explicitly invalid (11.3.1). */
static int moqdg_type_status_eog(u64 t) { return (t & 0x22) == 0x22; }

int moqdg_type_valid(u64 type) {
  return moqdg_type_form_ok(type) && !moqdg_type_status_eog(type);
}

/* Only Normal (0x0) Objects can carry Properties (11.3.1 / 11.2.1.2). */
static int moqdg_props_status_ok(const moqdg_obj* o) {
  return o->props.n == 0 || o->status == MOQDATA_STATUS_NORMAL;
}

/* ===== take (11.3.1) ===== */

static int moqdg_take_oid(wired_span buf, usz* at, moqdg_obj* o) {
  if (moqdg_type_zero_oid(o->type)) return 1;
  return moqvi_take(buf, at, &o->object_id);
}

static int moqdg_take_ids(wired_span buf, usz* at, moqdg_obj* o) {
  if (!moqvi_take(buf, at, &o->track_alias)) return 0;
  if (!moqvi_take(buf, at, &o->group_id)) return 0;
  return moqdg_take_oid(buf, at, o);
}

static int moqdg_take_prio(wired_span buf, usz* at, moqdg_obj* o) {
  if (moqdg_type_default_prio(o->type)) return 1;
  if (*at >= buf.n) return 0;
  o->priority = buf.p[(*at)++];
  return 1;
}

static int moqdg_take_props_body(
    wired_span buf, usz* at, u64 len, moqdg_obj* o) {
  if (len == 0) return MOQDATA_VIOLATION; /* PROPERTIES bit + length 0 */
  if (len > buf.n - *at) return MOQDATA_INSUFFICIENT;
  o->props = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  return MOQDATA_OK;
}

static int moqdg_take_props(wired_span buf, usz* at, moqdg_obj* o) {
  u64 len;
  if (!moqdg_type_props(o->type)) return MOQDATA_OK;
  if (!moqvi_take(buf, at, &len)) return MOQDATA_INSUFFICIENT;
  return moqdg_take_props_body(buf, at, len, o);
}

static int moqdg_take_status(wired_span buf, usz* at, moqdg_obj* o) {
  if (!moqvi_take(buf, at, &o->status)) return MOQDATA_INSUFFICIENT;
  if (!moqdg_props_status_ok(o)) return MOQDATA_VIOLATION;
  return MOQDATA_OK;
}

/* STATUS set: an Object Status and no payload; clear: the rest of the
 * datagram is the payload. */
static int moqdg_take_tail(wired_span buf, usz* at, moqdg_obj* o) {
  if (moqdg_type_status(o->type)) return moqdg_take_status(buf, at, o);
  o->payload = wired_span_of(buf.p + *at, buf.n - *at);
  *at        = buf.n;
  return MOQDATA_OK;
}

static int moqdg_take_head(wired_span buf, usz* at, moqdg_obj* o) {
  if (!moqdg_take_ids(buf, at, o)) return MOQDATA_INSUFFICIENT;
  if (!moqdg_take_prio(buf, at, o)) return MOQDATA_INSUFFICIENT;
  return MOQDATA_OK;
}

static int moqdg_take_rest(wired_span buf, usz* at, moqdg_obj* o) {
  int r = moqdg_take_props(buf, at, o);
  if (r != MOQDATA_OK) return r;
  return moqdg_take_tail(buf, at, o);
}

static int moqdg_take_body(wired_span buf, usz* at, moqdg_obj* o, usz* off) {
  int r = moqdg_take_head(buf, at, o);
  if (r != MOQDATA_OK) return r;
  r = moqdg_take_rest(buf, at, o);
  if (r != MOQDATA_OK) return r;
  *off = *at;
  return MOQDATA_OK;
}

int moqdg_take(wired_span buf, usz* off, moqdg_obj* out) {
  usz at = *off;
  u64 type;
  if (!moqvi_take(buf, &at, &type)) return MOQDATA_INSUFFICIENT;
  if (!moqdg_type_valid(type)) return MOQDATA_VIOLATION;
  *out      = (moqdg_obj){0};
  out->type = type;
  return moqdg_take_body(buf, &at, out, off);
}

/* ===== put (11.3.1) ===== */

static int moqdg_put_oid(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (moqdg_type_zero_oid(o->type)) return 1;
  return moqvi_put(buf, at, o->object_id);
}

static int moqdg_put_ids(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (!moqvi_put(buf, at, o->track_alias)) return 0;
  if (!moqvi_put(buf, at, o->group_id)) return 0;
  return moqdg_put_oid(buf, at, o);
}

static int moqdg_put_prio(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (moqdg_type_default_prio(o->type)) return 1;
  if (*at >= buf.n) return 0;
  buf.p[(*at)++] = (u8)o->priority;
  return 1;
}

static int moqdg_put_head(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (!moqvi_put(buf, at, o->type)) return 0;
  if (!moqdg_put_ids(buf, at, o)) return 0;
  return moqdg_put_prio(buf, at, o);
}

static int moqdg_put_props(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (!moqdg_type_props(o->type)) return 1;
  if (!moqvi_put(buf, at, o->props.n)) return 0;
  return bytes_put(buf, at, o->props);
}

static int moqdg_put_tail(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (moqdg_type_status(o->type)) return moqvi_put(buf, at, o->status);
  return bytes_put(buf, at, o->payload);
}

/* The PROPERTIES bit requires a non-empty Properties field (11.3.1). */
static int moqdg_put_props_ok(const moqdg_obj* o) {
  return !moqdg_type_props(o->type) || o->props.n != 0;
}

static int moqdg_put_valid(const moqdg_obj* o) {
  if (!moqdg_type_valid(o->type)) return 0;
  if (!moqdg_put_props_ok(o)) return 0;
  return moqdg_props_status_ok(o);
}

static int moqdg_put_body(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (!moqdg_put_head(buf, at, o)) return 0;
  if (!moqdg_put_props(buf, at, o)) return 0;
  return moqdg_put_tail(buf, at, o);
}

int moqdg_put(wired_mspan buf, usz* off, const moqdg_obj* o) {
  usz at = *off;
  if (!moqdg_put_valid(o)) return MOQDATA_VIOLATION;
  if (!moqdg_put_body(buf, &at, o)) return MOQDATA_INSUFFICIENT;
  *off = at;
  return MOQDATA_OK;
}
