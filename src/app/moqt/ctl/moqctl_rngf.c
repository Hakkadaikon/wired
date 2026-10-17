#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_rangeloc22_take_rest(
    u64 type, wired_span buf, usz* at, int* has_filter, moqctl_rangeloc* out);
static u64 moqctl_rangeloc22_wire_type_abs(const moqctl_rangeloc* r);
static u64 moqctl_rangeloc22_wire_type(const moqctl_rangeloc* r);
static int moqctl_rangeloc22_put_end_object(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r);
static int moqctl_rangeloc22_put_end(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r);
static int moqctl_rangeloc22_put_abs(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r);
static int moqctl_rangeloc22_put_body(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r);
static int moqctl_rangeloc22_put_none(wired_mspan buf, usz* off, usz at);
static int moqctl_rangeloc22_put_present(
    wired_mspan buf, usz* off, const moqctl_rangeloc* r);

/* type == 0x0 ("None") already consumed from *at; everything else goes
 * through moqctl_rangeloc22_body. */
static int moqctl_rangeloc22_take_rest(
    u64 type, wired_span buf, usz* at, int* has_filter, moqctl_rangeloc* out) {
  int r;
  if (type == 0x0) {
    *has_filter = 0;
    return MOQCTL_OK;
  }
  r = moqctl_rangeloc22_body(type, buf, at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *has_filter = 1;
  return MOQCTL_OK;
}

int moqctl_rangeloc22_take(
    wired_span buf, usz* off, int* has_filter, moqctl_rangeloc* out) {
  usz at = *off;
  u64 type;
  int r;
  *out = (moqctl_rangeloc){0};
  if (!moqvi_take(buf, &at, &type)) {
    return MOQCTL_INSUFFICIENT;
  }
  r = moqctl_rangeloc22_take_rest(type, buf, &at, has_filter, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *off = at;
  return MOQCTL_OK;
}

static u64 moqctl_rangeloc22_wire_type_abs(const moqctl_rangeloc* r) {
  if (r->ek == MOQCTL_REK_UNBOUNDED) {
    return 0x2;
  }
  return r->ek == MOQCTL_REK_GROUP ? 0x3 : 0x4;
}

static u64 moqctl_rangeloc22_wire_type(const moqctl_rangeloc* r) {
  if (r->sk == MOQCTL_RSK_REL_GROUP) {
    return 0x1;
  }
  if (r->sk == MOQCTL_RSK_NEXT_OBJ) {
    return 0x5;
  }
  return moqctl_rangeloc22_wire_type_abs(r);
}

static int moqctl_rangeloc22_put_end_object(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->ek != MOQCTL_REK_OBJ) {
    return 1;
  }
  return moqvi_put(buf, at, r->end_object);
}

static int moqctl_rangeloc22_put_end(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->ek == MOQCTL_REK_UNBOUNDED) {
    return 1;
  }
  if (!moqvi_put(buf, at, r->end_group - r->start_group)) {
    return 0;
  }
  return moqctl_rangeloc22_put_end_object(buf, at, r);
}

static int moqctl_rangeloc22_put_abs(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (!moqvi_put(buf, at, r->start_group)) {
    return 0;
  }
  if (!moqvi_put(buf, at, r->start_object)) {
    return 0;
  }
  return moqctl_rangeloc22_put_end(buf, at, r);
}

static int moqctl_rangeloc22_put_body(
    wired_mspan buf, usz* at, const moqctl_rangeloc* r) {
  if (r->sk == MOQCTL_RSK_REL_GROUP) {
    return moqvi_put(buf, at, r->start_group);
  }
  if (r->sk == MOQCTL_RSK_ABS) {
    return moqctl_rangeloc22_put_abs(buf, at, r);
  }
  return 1; /* NEXT_OBJ carries no fields */
}

static int moqctl_rangeloc22_put_none(wired_mspan buf, usz* off, usz at) {
  if (!moqvi_put(buf, &at, 0x0)) {
    return 0;
  }
  *off = at;
  return 1;
}

static int moqctl_rangeloc22_put_present(
    wired_mspan buf, usz* off, const moqctl_rangeloc* r) {
  usz at = *off;
  if (!moqvi_put(buf, &at, moqctl_rangeloc22_wire_type(r))) {
    return 0;
  }
  if (!moqctl_rangeloc22_put_body(buf, &at, r)) {
    return 0;
  }
  *off = at;
  return 1;
}

int moqctl_rangeloc22_put(
    wired_mspan buf, usz* off, int has_filter, const moqctl_rangeloc* r) {
  if (!has_filter) {
    return moqctl_rangeloc22_put_none(buf, off, *off);
  }
  return moqctl_rangeloc22_put_present(buf, off, r);
}

/* ===== Range Filter values (SS10.2.10-10.2.14) ===== */

int moqctl_rngf_has_prop(u64 ptype) {
  return ptype == MOQCTL_PARAM_OBJECT_PROPERTY_FILTER ||
         ptype == MOQCTL_PARAM_TRACK_PROPERTY_FILTER;
}
