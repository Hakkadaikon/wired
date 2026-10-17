#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_track_prop_has(wired_span props, u64 type, u64* v);
static int moqtrun_row_same_param(
    const wired_moqtrun_rngrow* a, const wired_moqtrun_rngrow* b);
static int moqtrun_tp_row_ok(
    const wired_moqtrun_req*    st,
    const wired_moqtrun_rngrow* r,
    wired_span                  props);
static int moqtrun_row_tp_of_set(const wired_moqtrun_rngrow* r, u8 set);
static int moqtrun_tp_set_pass(
    const wired_moqtrun_req* st, u8 set, wired_span props);
static void moqtrun_subtracks_note_rngf(
    wired_moqtrun_req* q, const moqctl_params* params);
static u64 moqtrun_subtracks_verdict(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqns_req* m);
static void moqtrun_subtracks_note_params(
    wired_moqtrun_req* q, const moqctl_params* params);

/* 1 iff Track Property type of props is present (a varint value), its
 * value in *v. */
static int moqtrun_track_prop_has(wired_span props, u64 type, u64* v) {
  usz    off  = 0;
  u64    prev = 0;
  int    has  = 0;
  moqkvp kv;
  while (moqtrun_kvp_next(props, &off, &prev, &kv)) {
    has |= moqtrun_prop_is_num(&kv, type);
    *v = moqtrun_prop_num_of(&kv, type, *v);
  }
  return has;
}

static int moqtrun_row_same_param(
    const wired_moqtrun_rngrow* a, const wired_moqtrun_rngrow* b) {
  return a->ptype == b->ptype && a->set_id == b->set_id &&
         a->prop_type == b->prop_type;
}

/* r's TRACK_PROPERTY_FILTER parameter (its Ranges OR'd) admits props:
 * the property must be present (3.3.2 "required Track Property types"). */
static int moqtrun_tp_row_ok(
    const wired_moqtrun_req*    st,
    const wired_moqtrun_rngrow* r,
    wired_span                  props) {
  u64 v   = 0;
  int hit = 0;
  if (!moqtrun_track_prop_has(props, r->prop_type, &v)) return 0;
  for (usz i = 0; i < st->rngf_n; i++)
    hit |= moqtrun_row_same_param(&st->rngf[i], r) &
           moqtrun_row_in(&st->rngf[i], v);
  return hit;
}

static int moqtrun_row_tp_of_set(const wired_moqtrun_rngrow* r, u8 set) {
  return moqtrun_row_dim_of_set(r, set, MOQCTL_PARAM_TRACK_PROPERTY_FILTER);
}

/* Every TRACK_PROPERTY_FILTER of one set admits props (AND'd, 3.3.2). */
static int moqtrun_tp_set_pass(
    const wired_moqtrun_req* st, u8 set, wired_span props) {
  int ok = 1;
  for (usz i = 0; i < st->rngf_n; i++)
    ok &= !moqtrun_row_tp_of_set(&st->rngf[i], set) |
          moqtrun_tp_row_ok(st, &st->rngf[i], props);
  return ok;
}

/* draft-22 3.3.2 / 9.20.14: t is offered to SUBSCRIBE_TRACKS st only when
 * some SetID's Track Property filters all admit its Track Properties (a
 * set without any passes here). ponytail: properties longer than
 * WIRED_MOQTRUN_TRACK_PROPS_MAX are not kept, so they read as absent. */
int moqtrun_subtracks_tp_pass(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t) {
  wired_span props = wired_span_of(t->props, t->props_len);
  int        pass  = !st->rngf_n;
  for (usz i = 0; i < st->rngf_n; i++)
    pass |= moqtrun_tp_set_pass(st, st->rngf[i].set_id, props);
  return pass;
}

/* draft-22 3.6.2 "These parameters are used by the publisher as the
 * initial Subscription parameters" (draft-19 10.19.1 "copied over as the
 * default Subscription parameters"): kept on q, as 9.8 lets no Range
 * Filter into the PUBLISH. */
static void moqtrun_subtracks_note_rngf(
    wired_moqtrun_req* q, const moqctl_params* params) {
  q->rngf_n = 0;
  for (usz i = 0; i < params->n; i++)
    moqtrun_subtracks_rngf_item(q, &params->items[i]);
}

/* draft-22 3.3.2 / draft-19 5.1.3: a malformed or repeated Range Filter, or
 * more Ranges than MAX_FILTER_RANGES, "MUST reject this with REQUEST_ERROR
 * with error code INVALID_FILTER" -- SUBSCRIBE_TRACKS too. */
static u64 moqtrun_subtracks_verdict(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqns_req* m) {
  u64 code = moqtrun_rngf_refusal(&m->params);
  if (code != MOQTRUN_REQ_ACCEPT) return code;
  return moqtrun_disc_verdict(hub, p->req, m, moqtrun_subtracks_check);
}

/* FORWARD and GROUP_ORDER are recorded as given, to be echoed on every
 * generated PUBLISH: d18/d19 10.19(.1) "will set the FORWARD parameter to
 * 0 ... to 1, or indicate that value by omitting"; draft-22 3.6.2 "explicitly
 * communicated in the PUBLISH" -- so a present FORWARD 1 is spelled out on
 * every draft. Absent ones stay omitted (0 for GROUP_ORDER). The object
 * Range Filters are kept too (moqtrun_subtracks_note_rngf). */
static void moqtrun_subtracks_note_params(
    wired_moqtrun_req* q, const moqctl_params* params) {
  const moqctl_param* f = moqctl_params_find(params, MOQCTL_PARAM_FORWARD);
  const moqctl_param* g = moqctl_params_find(params, MOQCTL_PARAM_GROUP_ORDER);
  q->has_forward        = f != 0;
  q->forward            = moqtrun_param_u8(f);
  q->group_order        = moqtrun_param_u8(g);
  moqtrun_subtracks_note_rngf(q, params);
}

/* Body of moqtrun_dispatch_subscribe_tracks once p->req and the decode are
 * known good, split out to keep the caller's own branch count at the gate. */
void moqtrun_subtracks_admit(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqns_req* m) {
  u64 code = moqtrun_subtracks_verdict(hub, p, m);
  if (code == MOQTRUN_REQ_ACCEPT)
    moqtrun_subtracks_note_params(p->req, &m->params);
  moqtrun_disc_answer(p, code);
}
