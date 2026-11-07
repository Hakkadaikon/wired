#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_params_take_step(
    wired_span buf, usz* at, u32 ctx, int ver, u64* prev, moqctl_params* out);
static int moqctl_params_take_loop(
    wired_span buf, usz* at, u32 ctx, int ver, u64 count, moqctl_params* out);
static void moqctl_param_flip(moqctl_param* p, u64 from, u64 to);
static void moqctl_params_flip(moqctl_params* params, u64 from, u64 to);

static int moqctl_params_take_step(
    wired_span buf, usz* at, u32 ctx, int ver, u64* prev, moqctl_params* out) {
  int r;
  if (out->n >= MOQCTL_MAX_PARAMS) {
    return MOQCTL_VIOLATION;
  }
  r = moqctl_param_take_one(buf, at, ctx, ver, *prev, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *prev = out->items[out->n - 1].type;
  return MOQCTL_OK;
}

static int moqctl_params_take_loop(
    wired_span buf, usz* at, u32 ctx, int ver, u64 count, moqctl_params* out) {
  u64 prev = 0;
  for (u64 i = 0; i < count; i++) {
    int r = moqctl_params_take_step(buf, at, ctx, ver, &prev, out);
    if (r != MOQCTL_OK) {
      return r;
    }
  }
  return MOQCTL_OK;
}

/* draft-23 9.19.18: PAUSED is FORWARD inverted; p of Type from becomes
 * Type to with the other value. */
static void moqctl_param_flip(moqctl_param* p, u64 from, u64 to) {
  if (p->type == from) {
    p->type = to;
    p->u8v  = !p->u8v;
  }
}

static void moqctl_params_flip(moqctl_params* params, u64 from, u64 to) {
  for (usz i = 0; i < params->n; i++) {
    moqctl_param_flip(&params->items[i], from, to);
  }
}

void moqctl_params_out(int ver, moqctl_params* params) {
  if (moqver_caps(ver) & MOQVER_CAP_PAUSED) {
    moqctl_params_flip(params, MOQCTL_PARAM_FORWARD, MOQCTL_PARAM_PAUSED);
  }
}

/* PAUSED (only a draft-23 table admits it) is kept as FORWARD. */
int moqctl_params_take(
    int ver, wired_span buf, usz* off, u32 ctx, moqctl_params* out) {
  usz at = *off;
  u64 count;
  int r;
  out->n = 0;
  if (!moqvi_take(buf, &at, &count)) {
    return MOQCTL_INSUFFICIENT;
  }
  r = moqctl_params_take_loop(buf, &at, ctx, ver, count, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  moqctl_params_flip(out, MOQCTL_PARAM_PAUSED, MOQCTL_PARAM_FORWARD);
  *off = at;
  return MOQCTL_OK;
}

int moqctl_param_put_uint8(wired_mspan buf, usz* at, u64 v) {
  if (*at + 1 > buf.n) {
    return 0;
  }
  buf.p[*at] = (u8)v;
  *at += 1;
  return 1;
}

int moqctl_pp_uint8(wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqctl_param_put_uint8(buf, at, p->u8v);
}

int moqctl_pp_varint(wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqvi_put(buf, at, p->vi);
}

int moqctl_pp_location(wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqctl_loc_put(buf, at, p->loc);
}

int moqctl_pp_bytes(wired_mspan buf, usz* at, const moqctl_param* p) {
  if (!moqvi_put(buf, at, p->bytes.n)) {
    return 0;
  }
  return bytes_put(buf, at, p->bytes);
}

/* moqkvp_take's failures (index -r) as decode results: a cut pair is a
 * Length mismatch (draft-23 8.3 for the other two). */
static const int moqctl_kvp_r_tbl[] = {
    MOQCTL_VIOLATION, MOQCTL_VIOLATION, MOQCTL_R_DELTA, MOQCTL_R_FIELD_LEN};

int moqctl_kvp_r(int r) { return moqctl_kvp_r_tbl[-r]; }
