#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_filter_inverted(const moqctl_rangeloc* f);
static int moqtrun_params_inverted(const moqctl_params* params);
static int moqtrun_rngf_dup_pair(
    const moqctl_rangefilter* a, const moqctl_rangefilter* b);
static int moqtrun_rngf_dup_j(
    const moqctl_params* params, usz j, u64 type, const moqctl_rangefilter* fi);
static int moqtrun_rngf_dup_before(
    const moqctl_params* params, usz i, const moqctl_rangefilter* fi);
static void moqtrun_rngf_scan_one(
    const moqctl_params* params, usz i, moqtrun_rngf_scan* s);
static moqtrun_rngf_scan moqtrun_rngf_scan_msg(const moqctl_params* params);
static u64               moqtrun_subscribe_refusal_tail(
    const wired_moqt_hub* hub, const moqctl_subscribe* m);

/* Reserved namespaces first (2.4.2/2.4.3: never published under), then
 * authorization. */
int moqtrun_publish_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code) {
  *code = MOQCTL_ERR_DOES_NOT_EXIST;
  if (moqtrun_ns_reserved(&m->name.ns)) {
    return 1;
  }
  return moqtrun_publish_auth_refused(hub, m, code);
}

/* draft-22 0x04 whose End Object precedes its Start Object in the same
 * Group: no Object can pass (SS9.20.9; INVALID_RANGE, SS12.3). */
static int moqtrun_filter_inverted(const moqctl_rangeloc* f) {
  return f->ek == MOQCTL_REK_OBJ &&
         moqctl_loc_less(
             moqctl_loc_of(f->end_group, f->end_object),
             moqctl_loc_of(f->start_group, f->start_object));
}

static int moqtrun_params_inverted(const moqctl_params* params) {
  const moqctl_param* f =
      moqctl_params_find(params, MOQCTL_PARAM_LOCATION_FILTER);
  return moqtrun_param_has_filter(f) && moqtrun_filter_inverted(&f->rl);
}

static int moqtrun_rngf_dup_pair(
    const moqctl_rangefilter* a, const moqctl_rangefilter* b) {
  return a->set_id == b->set_id && a->prop_type == b->prop_type;
}

static int moqtrun_rngf_dup_j(
    const moqctl_params*      params,
    usz                       j,
    u64                       type,
    const moqctl_rangefilter* fi) {
  moqctl_rangefilter fj;
  if (params->items[j].type != type) {
    return 0;
  }
  moqtrun_rngf_of(&params->items[j], &fj);
  return moqtrun_rngf_dup_pair(fi, &fj);
}

/* A repeated (Type, SetID, Property Type) identity earlier in the same
 * message (10.2.10: INVALID_FILTER). */
static int moqtrun_rngf_dup_before(
    const moqctl_params* params, usz i, const moqctl_rangefilter* fi) {
  for (usz j = 0; j < i; j++) {
    if (moqtrun_rngf_dup_j(params, j, params->items[i].type, fi)) {
      return 1;
    }
  }
  return 0;
}

static void moqtrun_rngf_scan_one(
    const moqctl_params* params, usz i, moqtrun_rngf_scan* s) {
  moqctl_rangefilter f;
  if (!moqtrun_rngf_of(&params->items[i], &f)) {
    return;
  }
  s->count += f.n;
  s->bad |= f.invalid | moqtrun_rngf_dup_before(params, i, &f);
}

static moqtrun_rngf_scan moqtrun_rngf_scan_msg(const moqctl_params* params) {
  moqtrun_rngf_scan s = {0, 0};
  for (usz i = 0; i < params->n; i++) {
    moqtrun_rngf_scan_one(params, i, &s);
  }
  return s;
}

/* INVALID_FILTER (10.2.10/10.4) for a malformed Range Filter value, a
 * repeated (Type, SetID, Property Type) identity, or more Ranges than
 * the hub's advertised MAX_FILTER_RANGES; ACCEPT otherwise. */
u64 moqtrun_rngf_refusal(const moqctl_params* params) {
  moqtrun_rngf_scan s = moqtrun_rngf_scan_msg(params);
  if (s.bad || s.count > WIRED_MOQTRUN_MAX_FILTER_RANGES) {
    return MOQCTL_ERR_INVALID_FILTER;
  }
  return MOQTRUN_REQ_ACCEPT;
}

/* Rows n rows would hold after params replace the types it mentions:
 * kept types plus the message's (10.4: MAX_FILTER_RANGES bounds the
 * concurrent total). */
int moqtrun_rngf_rows_over(
    const wired_moqtrun_rngrow* rows, usz n, const moqctl_params* params) {
  usz kept = 0;
  for (usz i = 0; i < n; i++) {
    kept += !moqtrun_rngf_msg_has(params, rows[i].ptype);
  }
  return kept + moqtrun_rngf_scan_msg(params).count >
         WIRED_MOQTRUN_MAX_FILTER_RANGES;
}

int moqtrun_rngf_over(const wired_moqtrun_sub* s, const moqctl_params* params) {
  return moqtrun_rngf_rows_over(s->rngf, s->rngf_n, params);
}

/* REQUEST_ERROR code a SUBSCRIBE's or REQUEST_UPDATE's parameters call
 * for: a bad Range Filter, an unsatisfiable Location Filter. */
u64 moqtrun_params_refusal(const moqctl_params* params) {
  u64 code = moqtrun_rngf_refusal(params);
  if (code != MOQTRUN_REQ_ACCEPT) {
    return code;
  }
  return moqtrun_params_inverted(params) ? MOQCTL_ERR_INVALID_RANGE
                                         : MOQTRUN_REQ_ACCEPT;
}

static u64 moqtrun_subscribe_refusal_tail(
    const wired_moqt_hub* hub, const moqctl_subscribe* m) {
  u64 code = moqtrun_params_refusal(&m->params);
  if (code != MOQTRUN_REQ_ACCEPT) {
    return code;
  }
  return moqtrun_subscribe_refused(hub, m, &code) ? code : MOQTRUN_REQ_ACCEPT;
}

/* Reserved namespaces first (2.4.2/2.4.3), then parameters and
 * authorization. */
u64 moqtrun_subscribe_refusal(
    const wired_moqt_hub* hub, const moqctl_subscribe* m) {
  if (moqtrun_ns_reserved(&m->name.ns)) {
    return MOQCTL_ERR_DOES_NOT_EXIST;
  }
  return moqtrun_subscribe_refusal_tail(hub, m);
}
