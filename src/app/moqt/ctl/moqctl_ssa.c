#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_pp_locfilter(wired_mspan buf, usz* at, const moqctl_param* p);
static int moqctl_pp_raw(wired_mspan buf, usz* at, const moqctl_param* p);
static int moqctl_pp_rangeloc22(
    wired_mspan buf, usz* at, const moqctl_param* p);
static int moqctl_pp_lenpref(wired_mspan buf, usz* at, const u8* tmp, usz n);
static int moqctl_sw_put_val(
    wired_mspan b, usz* at, const moqctl_switchfrom* s);
static int moqctl_pp_switchfrom(
    wired_mspan buf, usz* at, const moqctl_param* p);
static int moqctl_ssa_put_vis(wired_mspan b, usz* at, const moqctl_ssa* s);
static int moqctl_ssa_put_rank(wired_mspan b, usz* at, const moqctl_ssa* s);
static int moqctl_ssa_put_val(wired_mspan b, usz* at, const moqctl_ssa* s);
static int moqctl_pp_ssa(wired_mspan buf, usz* at, const moqctl_param* p);

static int moqctl_pp_locfilter(
    wired_mspan buf, usz* at, const moqctl_param* p) {
  u8  tmp[MOQCTL_LOCFILTER_MAX];
  usz n = 0;
  if (!moqctl_locfilter_put(wired_mspan_of(tmp, sizeof tmp), &n, &p->lf))
    return 0;
  if (!moqvi_put(buf, at, n)) return 0;
  return bytes_put(buf, at, wired_span_of(tmp, n));
}

static int moqctl_pp_raw(wired_mspan buf, usz* at, const moqctl_param* p) {
  return bytes_put(buf, at, p->bytes);
}

static int moqctl_pp_rangeloc22(
    wired_mspan buf, usz* at, const moqctl_param* p) {
  return moqctl_rangeloc22_put(buf, at, p->has_filter, &p->rl);
}

/* Length + the n value bytes already built in tmp. */
static int moqctl_pp_lenpref(wired_mspan buf, usz* at, const u8* tmp, usz n) {
  if (!moqvi_put(buf, at, n)) return 0;
  return bytes_put(buf, at, wired_span_of(tmp, n));
}

static int moqctl_sw_put_val(
    wired_mspan b, usz* at, const moqctl_switchfrom* s) {
  if (!moqvi_put(b, at, s->request_id)) return 0;
  if (!moqvi_put(b, at, s->mode)) return 0;
  return moqctl_param_put_uint8(b, at, (u64)(s->publish_done != 0) << 7);
}

static int moqctl_pp_switchfrom(
    wired_mspan buf, usz* at, const moqctl_param* p) {
  u8  tmp[MOQCTL_SW_VAL_MAX];
  usz n = 0;
  if (p->sw.mode > MOQCTL_SWITCH_SOFT) return 0; /* never send a bad Mode */
  if (!moqctl_sw_put_val(wired_mspan_of(tmp, sizeof tmp), &n, &p->sw)) return 0;
  return moqctl_pp_lenpref(buf, at, tmp, n);
}

static int moqctl_ssa_put_vis(wired_mspan b, usz* at, const moqctl_ssa* s) {
  const u64 f[MOQCTL_SSA_VIS] = {
      s->set_id, s->algorithm_id, s->threshold_kbps, s->weight, s->activate};
  for (usz i = 0; i < MOQCTL_SSA_VIS; i++)
    if (!moqvi_put(b, at, f[i])) return 0;
  return 1;
}

static int moqctl_ssa_put_rank(wired_mspan b, usz* at, const moqctl_ssa* s) {
  if (!s->has_rank) return 1;
  return moqctl_param_put_uint8(b, at, s->rank);
}

static int moqctl_ssa_put_val(wired_mspan b, usz* at, const moqctl_ssa* s) {
  if (!moqctl_ssa_put_vis(b, at, s)) return 0;
  return moqctl_ssa_put_rank(b, at, s);
}

static int moqctl_pp_ssa(wired_mspan buf, usz* at, const moqctl_param* p) {
  u8  tmp[MOQCTL_SSA_VAL_MAX];
  usz n = 0;
  if (!moqctl_ssa_weight_ok(p->ssa.weight)) return 0; /* never send it */
  if (!moqctl_ssa_put_val(wired_mspan_of(tmp, sizeof tmp), &n, &p->ssa))
    return 0;
  return moqctl_pp_lenpref(buf, at, tmp, n);
}

/* PENC_TOKEN re-emits the raw Token bytes the sender placed in p->bytes
 * (this subset only receives tokens; no Token-structure encoder). */
const moqctl_param_put_fn MOQCTL_PARAM_PUT_FNS[10] = {
    moqctl_pp_uint8, moqctl_pp_varint,     moqctl_pp_location,
    moqctl_pp_bytes, moqctl_pp_bytes,      moqctl_pp_locfilter,
    moqctl_pp_raw,   moqctl_pp_rangeloc22, moqctl_pp_switchfrom,
    moqctl_pp_ssa};
