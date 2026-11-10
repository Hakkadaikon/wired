#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_rangeloc22_take_start(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc22_abs_start_group_end(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc22_abs_range(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc22_relative_start(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc22_abs_start(
    wired_span buf, usz* at, moqctl_rangeloc* out);
static int moqctl_rangeloc22_next_object_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out);

/* ----- draft-22 (SS9.20.9): type 0x00..0x05 -----
 * Same one-function-per-type + table-dispatch shape as d19
 * (moqctl_rangeloc19.c). */

static int moqctl_rangeloc22_take_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_ABS;
  if (!moqvi_take(buf, at, &out->start_group)) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqvi_take(buf, at, &out->start_object) ? MOQCTL_OK
                                                 : MOQCTL_INSUFFICIENT;
}

static int moqctl_rangeloc22_abs_start_group_end(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc22_take_start(buf, at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  out->ek = MOQCTL_REK_GROUP;
  return moqctl_rangeloc_take_end_group(
      buf, at, out->start_group, &out->end_group);
}

static int moqctl_rangeloc22_abs_range(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc22_abs_start_group_end(buf, at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  out->ek = MOQCTL_REK_OBJ;
  return moqvi_take(buf, at, &out->end_object) ? MOQCTL_OK
                                               : MOQCTL_INSUFFICIENT;
}

static int moqctl_rangeloc22_relative_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  out->sk = MOQCTL_RSK_REL_GROUP;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return moqvi_take(buf, at, &out->start_group) ? MOQCTL_OK
                                                : MOQCTL_INSUFFICIENT;
}

static int moqctl_rangeloc22_abs_start(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  int r = moqctl_rangeloc22_take_start(buf, at, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

static int moqctl_rangeloc22_next_object_fn(
    wired_span buf, usz* at, moqctl_rangeloc* out) {
  (void)buf;
  (void)at;
  out->sk = MOQCTL_RSK_NEXT_OBJ;
  out->ek = MOQCTL_REK_UNBOUNDED;
  return MOQCTL_OK;
}

/* Index 0 unused (type 0 is "no filter", handled before dispatch);
 * indices 1..5 are Relative Start .. Next Object. */
static const moqctl_rangeloc22_fn MOQCTL_RANGELOC22_FNS[6] = {
    0,
    moqctl_rangeloc22_relative_start,
    moqctl_rangeloc22_abs_start,
    moqctl_rangeloc22_abs_start_group_end,
    moqctl_rangeloc22_abs_range,
    moqctl_rangeloc22_next_object_fn};

int moqctl_rangeloc22_body(
    u64 type, wired_span buf, usz* at, moqctl_rangeloc* out) {
  if (type == 0 || type >= MOQCTL_RANGELOC22_FNS_N) {
    return MOQCTL_R_PARAM; /* draft-23 9.19.9 */
  }
  return MOQCTL_RANGELOC22_FNS[type](buf, at, out);
}
