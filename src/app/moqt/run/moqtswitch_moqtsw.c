#include "app/moqt/run/moqtswitch_impl.h"

static int moqtsw_pending(const wired_moqtrun_sub* s);
static int moqtsw_in_set(const wired_moqtrun_sub* s);
static int moqtsw_free(const wired_moqtrun_sub* s);
static int moqtsw_hub_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static int moqtsw_peer_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static int moqtsw_target_ok(const wired_moqt_hub* hub, const moqtsw_req* r);
static int moqtsw_old_ok(
    const wired_moqtrun_sub*   old,
    const wired_moqtrun_track* ot,
    const wired_moqtrun_track* t);
static int moqtsw_valid(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    const moqtsw_req*        r,
    const moqctl_switchfrom* sw);
static int moqtsw_conflict(const moqctl_params* params);
static u64 moqtsw_shape(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    const moqtsw_req*        r,
    const moqctl_params*     params,
    const moqctl_switchfrom* sw);
static int moqtsw_off(const wired_moqt_hub* hub, const moqctl_params* params);

const moqctl_param* moqtsw_param(const moqctl_params* params) {
  return moqctl_params_find(params, MOQCTL_PARAM_SWITCH_FROM);
}

/* s is switching away already (a second switch from it is refused). */
static int moqtsw_pending(const wired_moqtrun_sub* s) {
  return s && s->sw_role == MOQTSW_ROLE_OLD;
}

/* s is a switching-set member (SSTS, moqtssts_run.c): SWITCH_FROM and
 * SSTS are not combined. Reads the field W4b's moqtss_sub_in_set reads,
 * keeping this module free of moqtssts_run.c symbols. */
static int moqtsw_in_set(const wired_moqtrun_sub* s) { return s && s->ssts_on; }

/* s may take part in a switch: not already switching away, in no set. */
static int moqtsw_free(const wired_moqtrun_sub* s) {
  return !moqtsw_pending(s) && !moqtsw_in_set(s);
}

static int moqtsw_hub_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t == &hub->blob_track || t == &hub->live.track;
}

/* The activating side can take a switch: a live peer track the session
 * does not hold yet, itself not switching away. */
static int moqtsw_peer_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t && !moqtsw_hub_track(hub, t);
}

static int moqtsw_target_ok(const wired_moqt_hub* hub, const moqtsw_req* r) {
  return moqtsw_peer_track(hub, r->t) && !r->held && moqtsw_free(r->self);
}

/* The named subscription can be stopped: live, on another track, not
 * switching away already, in no switching set. */
static int moqtsw_old_ok(
    const wired_moqtrun_sub*   old,
    const wired_moqtrun_track* ot,
    const wired_moqtrun_track* t) {
  return old && ot != t && moqtsw_free(old);
}

static int moqtsw_valid(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    const moqtsw_req*        r,
    const moqctl_switchfrom* sw) {
  wired_moqtrun_track* ot = 0;
  if (sw->request_id == r->rid || !moqtsw_target_ok(hub, r)) {
    return 0;
  }
  return moqtsw_old_ok(ops->find(hub, r->idx, sw->request_id, &ot), ot, r->t);
}

/* Parameters a SWITCH_FROM cannot share a message with: FORWARD (the
 * switch decides the activating side's Forward State itself, moqtail
 * plan_switch), FILL_PARAMETERS (a fill delivers Groups below G: NoDup)
 * and SWITCHING_SET_ASSIGNMENT (SSTS and SWITCH_FROM are not combined). */
static const u64 MOQTSW_CONFLICTS[] = {
    MOQCTL_PARAM_FORWARD, MOQCTL_PARAM_FILL_PARAMETERS,
    MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT};

static int moqtsw_conflict(const moqctl_params* params) {
  for (usz i = 0; i < sizeof MOQTSW_CONFLICTS / sizeof MOQTSW_CONFLICTS[0];
       i++) {
    if (moqctl_params_find(params, MOQTSW_CONFLICTS[i])) {
      return 1;
    }
  }
  return 0;
}

static u64 moqtsw_shape(
    wired_moqt_hub*          hub,
    const moqtsw_ops*        ops,
    const moqtsw_req*        r,
    const moqctl_params*     params,
    const moqctl_switchfrom* sw) {
  if (moqtsw_conflict(params)) {
    return MOQCTL_ERR_INVALID_SWITCH;
  }
  return moqtsw_valid(hub, ops, r, sw) ? MOQTSW_ACCEPT
                                       : MOQCTL_ERR_INVALID_SWITCH;
}

u64 moqtsw_verdict(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    const moqtsw_req*    r,
    const moqctl_params* params) {
  const moqctl_param* p = moqtsw_param(params);
  return p ? moqtsw_shape(hub, ops, r, params, &p->sw) : MOQTSW_ACCEPT;
}

/* SWITCH_FROM present while switching is off. */
static int moqtsw_off(const wired_moqt_hub* hub, const moqctl_params* params) {
  return !hub->switch_track && moqtsw_param(params);
}

int moqtsw_take(const wired_moqt_hub* hub, int r, const moqctl_params* params) {
  if (r != MOQCTL_OK) {
    return r;
  }
  return moqtsw_off(hub, params) ? MOQCTL_VIOLATION : MOQCTL_OK;
}

u64 moqtsw_pub_refusal(const moqctl_params* params, u64 prior) {
  if (prior != MOQTSW_ACCEPT) {
    return prior;
  }
  return moqtsw_param(params) ? MOQCTL_ERR_INVALID_SWITCH : MOQTSW_ACCEPT;
}

u64 moqtsw_sub_refusal(const moqctl_params* params, int hub_track, u64 prior) {
  if (prior != MOQTSW_ACCEPT) {
    return prior;
  }
  return hub_track ? moqtsw_pub_refusal(params, prior) : MOQTSW_ACCEPT;
}

u64 moqtsw_check(
    wired_moqt_hub*            hub,
    const moqtsw_ops*          ops,
    usz                        idx,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   held,
    u64                        rid,
    const moqctl_params*       params) {
  moqtsw_req r = {idx, t, 0, held, rid};
  return moqtsw_verdict(hub, ops, &r, params);
}
