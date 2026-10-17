#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_pv_ns(wired_span buf, usz* at, moqctl_param* p);
static int moqctl_pv_rangeloc22(wired_span buf, usz* at, moqctl_param* p);
static int moqctl_sw_take_mode(wired_span v, usz* at, moqctl_switchfrom* s);
static int moqctl_sw_take_flags(wired_span v, usz at, moqctl_switchfrom* s);
static int moqctl_sw_take(wired_span v, moqctl_switchfrom* s);
static int moqctl_pv_switchfrom(wired_span buf, usz* at, moqctl_param* p);
static int moqctl_ssa_take_vis(wired_span v, usz* at, moqctl_ssa* s);
static int moqctl_ssa_take_rank(wired_span v, usz at, moqctl_ssa* s);
static int moqctl_ssa_take(wired_span v, moqctl_ssa* s);
static int moqctl_pv_ssa(wired_span buf, usz* at, moqctl_param* p);

static int moqctl_pv_ns(wired_span buf, usz* at, moqctl_param* p) {
  moqctl_ns ns;
  usz       start = *at;
  int       r     = moqctl_ns_take(buf, at, &ns);
  p->bytes        = wired_span_of(buf.p + start, *at - start);
  return r;
}

/* draft-22 LOCATION_FILTER (SS9.20.9): no Length prefix at all. */
static int moqctl_pv_rangeloc22(wired_span buf, usz* at, moqctl_param* p) {
  return moqctl_rangeloc22_take(buf, at, &p->has_filter, &p->rl);
}

/* ----- SWITCH_FROM (moqtail): RequestID, Mode, Flags ----- */

static int moqctl_sw_take_mode(wired_span v, usz* at, moqctl_switchfrom* s) {
  u64 mode;
  if (!moqvi_take(v, at, &mode) || mode > MOQCTL_SWITCH_SOFT)
    return MOQCTL_VIOLATION;
  s->mode = (u8)mode;
  return MOQCTL_OK;
}

/* Flags is the last byte: exactly one left, only bit 0x80 may be set. */
static int moqctl_sw_take_flags(wired_span v, usz at, moqctl_switchfrom* s) {
  if (v.n - at != 1) return MOQCTL_VIOLATION;
  if (v.p[at] & 0x7f) return MOQCTL_VIOLATION;
  s->publish_done = (u8)(v.p[at] >> 7);
  return MOQCTL_OK;
}

static int moqctl_sw_take(wired_span v, moqctl_switchfrom* s) {
  usz at = 0;
  if (!moqvi_take(v, &at, &s->request_id)) return MOQCTL_VIOLATION;
  if (moqctl_sw_take_mode(v, &at, s) != MOQCTL_OK) return MOQCTL_VIOLATION;
  return moqctl_sw_take_flags(v, at, s);
}

static int moqctl_pv_switchfrom(wired_span buf, usz* at, moqctl_param* p) {
  int r = moqctl_pv_bytes(buf, at, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_sw_take(p->bytes, &p->sw);
}

static int moqctl_ssa_take_vis(wired_span v, usz* at, moqctl_ssa* s) {
  u64* f[MOQCTL_SSA_VIS] = {
      &s->set_id, &s->algorithm_id, &s->threshold_kbps, &s->weight,
      &s->activate};
  for (usz i = 0; i < MOQCTL_SSA_VIS; i++)
    if (!moqvi_take(v, at, f[i])) return MOQCTL_VIOLATION;
  return MOQCTL_OK;
}

int moqctl_ssa_weight_ok(u64 w) { return w >= 1 && w <= 10; }

/* Rank is optional: nothing left, or exactly one byte. */
static int moqctl_ssa_take_rank(wired_span v, usz at, moqctl_ssa* s) {
  if (at == v.n) return MOQCTL_OK;
  if (v.n - at != 1) return MOQCTL_VIOLATION;
  s->rank     = v.p[at];
  s->has_rank = 1;
  return MOQCTL_OK;
}

static int moqctl_ssa_take(wired_span v, moqctl_ssa* s) {
  usz at = 0;
  if (moqctl_ssa_take_vis(v, &at, s) != MOQCTL_OK) return MOQCTL_VIOLATION;
  if (!moqctl_ssa_weight_ok(s->weight)) return MOQCTL_VIOLATION;
  return moqctl_ssa_take_rank(v, at, s);
}

static int moqctl_pv_ssa(wired_span buf, usz* at, moqctl_param* p) {
  int r = moqctl_pv_bytes(buf, at, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_ssa_take(p->bytes, &p->ssa);
}

const moqctl_param_value_fn MOQCTL_PARAM_VALUE_FNS[10] = {
    moqctl_pv_uint8, moqctl_pv_varint,     moqctl_pv_location,
    moqctl_pv_bytes, moqctl_pv_token,      moqctl_pv_locfilter,
    moqctl_pv_ns,    moqctl_pv_rangeloc22, moqctl_pv_switchfrom,
    moqctl_pv_ssa};
