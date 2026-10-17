#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_param_take_value(
    wired_span buf, usz* at, int enc, moqctl_param* p);
static int moqctl_param_in_range(
    const moqctl_param_rule* rule, const moqctl_param* p);
static int moqctl_param_take_checked(
    wired_span buf, usz* at, const moqctl_param_rule* rule, moqctl_param* p);
static int moqctl_param_dup(const moqctl_params* out, u64 type);
static int moqctl_param_fresh(
    const moqctl_param_rule* rule, const moqctl_params* out, u64 type);
static int moqctl_param_admit(
    const moqctl_param_rule* rule,
    int                      ver,
    u32                      ctx,
    const moqctl_params*     out,
    u64                      t);
static int moqctl_param_take_delta(
    wired_span buf, usz* at, u64 prev, moqctl_param* p);
static int  moqctl_param_typed_filter(const moqctl_param_rule* rule, int ver);
static void moqctl_param_rule_select(
    const moqctl_param_rule* rule, int ver, moqctl_param_rule* over);
static int moqctl_param_take_body(
    wired_span     buf,
    usz*           at,
    u32            ctx,
    int            ver,
    moqctl_params* out,
    moqctl_param*  p);

static int moqctl_param_take_value(
    wired_span buf, usz* at, int enc, moqctl_param* p) {
  return MOQCTL_PARAM_VALUE_FNS[enc](buf, at, p);
}

static int moqctl_param_in_range(
    const moqctl_param_rule* rule, const moqctl_param* p) {
  if (rule->enc != MOQCTL_PENC_UINT8) return 1;
  return p->u8v >= rule->lo && p->u8v <= rule->hi;
}

/* FORWARD outside {0,1} (SS10.2.17) and GROUP_ORDER outside {1,2}
 * (SS10.2.8) MUST close the session with PROTOCOL_VIOLATION. */
static int moqctl_param_take_checked(
    wired_span buf, usz* at, const moqctl_param_rule* rule, moqctl_param* p) {
  int r = moqctl_param_take_value(buf, at, rule->enc, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_param_in_range(rule, p) ? MOQCTL_OK : MOQCTL_VIOLATION;
}

static int moqctl_param_dup(const moqctl_params* out, u64 type) {
  for (usz i = 0; i < out->n; i++)
    if (out->items[i].type == type) return 1;
  return 0;
}

/* A Type already in out may come again only where its definition allows
 * repeats (SS10.2). */
static int moqctl_param_fresh(
    const moqctl_param_rule* rule, const moqctl_params* out, u64 type) {
  return rule->repeat || !moqctl_param_dup(out, type);
}

/* Unknown Type is always a VIOLATION per SS10.2 (no skip mechanism
 * exists); so is a known one outside ver's ctx or repeated. */
static int moqctl_param_admit(
    const moqctl_param_rule* rule,
    int                      ver,
    u32                      ctx,
    const moqctl_params*     out,
    u64                      t) {
  return moqctl_param_allowed_in(rule, ver, ctx) &&
         moqctl_param_fresh(rule, out, t);
}

static int moqctl_param_take_delta(
    wired_span buf, usz* at, u64 prev, moqctl_param* p) {
  u64 delta;
  if (!moqvi_take(buf, at, &delta)) return MOQCTL_INSUFFICIENT;
  return u64_add_ok(prev, delta, &p->type) ? MOQCTL_OK : MOQCTL_VIOLATION;
}

/* d22's LOCATION_FILTER is the only Type whose wire shape differs from
 * d19's (SS9.20.9, no Length, vs SS5.1.2); scopes live in the table. */
static int moqctl_param_typed_filter(const moqctl_param_rule* rule, int ver) {
  return rule->type == MOQCTL_PARAM_LOCATION_FILTER &&
         (moqver_caps(ver) & MOQVER_CAP_LOCFILTER_TYPED);
}

static void moqctl_param_rule_select(
    const moqctl_param_rule* rule, int ver, moqctl_param_rule* over) {
  *over = *rule;
  if (moqctl_param_typed_filter(rule, ver)) over->enc = MOQCTL_PENC_RANGELOC22;
}

static int moqctl_param_take_body(
    wired_span     buf,
    usz*           at,
    u32            ctx,
    int            ver,
    moqctl_params* out,
    moqctl_param*  p) {
  const moqctl_param_rule* rule = moqctl_param_rule_for(p->type);
  moqctl_param_rule        over = {0};
  if (!rule) return MOQCTL_VIOLATION;
  moqctl_param_rule_select(rule, ver, &over);
  if (!moqctl_param_admit(&over, ver, ctx, out, p->type))
    return MOQCTL_VIOLATION;
  p->enc = over.enc;
  return moqctl_param_take_checked(buf, at, &over, p);
}

int moqctl_param_take_one(
    wired_span buf, usz* at, u32 ctx, int ver, u64 prev, moqctl_params* out) {
  moqctl_param p = {0};
  int          r = moqctl_param_take_delta(buf, at, prev, &p);
  if (r != MOQCTL_OK) return r;
  r = moqctl_param_take_body(buf, at, ctx, ver, out, &p);
  if (r != MOQCTL_OK) return r;
  out->items[out->n] = p;
  out->n++;
  return MOQCTL_OK;
}
