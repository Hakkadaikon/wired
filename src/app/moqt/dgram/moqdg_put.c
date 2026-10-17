#include "app/moqt/dgram/moqdg_impl.h"

static int moqdg_take_body(wired_span buf, usz* at, moqdg_obj* o, usz* off);
static int moqdg_put_oid(wired_mspan buf, usz* at, const moqdg_obj* o);
static int moqdg_put_ids(wired_mspan buf, usz* at, const moqdg_obj* o);
static int moqdg_put_prio(wired_mspan buf, usz* at, const moqdg_obj* o);
static int moqdg_put_head(wired_mspan buf, usz* at, const moqdg_obj* o);
static int moqdg_put_props(wired_mspan buf, usz* at, const moqdg_obj* o);
static int moqdg_put_tail(wired_mspan buf, usz* at, const moqdg_obj* o);
static int moqdg_put_props_ok(const moqdg_obj* o);

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

int moqdg_put_valid(const moqdg_obj* o) {
  if (!moqdg_type_valid(o->type)) return 0;
  if (!moqdg_put_props_ok(o)) return 0;
  return moqdg_props_status_ok(o);
}

int moqdg_put_body(wired_mspan buf, usz* at, const moqdg_obj* o) {
  if (!moqdg_put_head(buf, at, o)) return 0;
  if (!moqdg_put_props(buf, at, o)) return 0;
  return moqdg_put_tail(buf, at, o);
}
