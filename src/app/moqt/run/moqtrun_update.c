#include "app/moqt/run/moqtrun_impl.h"

static u64 moqtrun_upd_checked(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);
static u64 moqtrun_upd_verdict(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);
static void moqtrun_update_sub_apply(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_sub*   s,
    wired_moqtrun_track* t,
    const moqctl_params* params,
    u64                  rid);
static int moqtrun_upd_sw_refused(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    usz                        idx,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);

/* Parameters are refused as on SUBSCRIBE (moqtrun_params_refusal). */
static u64 moqtrun_upd_checked(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  u64 code = moqtss_upd_check( /* SSTS (moqtssts_run.c) */
      hub, s, params, moqtrun_ssts_settable(hub, p, t),
      moqtrun_params_refusal(params));
  if (code != MOQTRUN_REQ_ACCEPT) {
    return code;
  }
  if (!moqtrun_upd_apply(hub, p, s, t, params)) {
    return MOQCTL_ERR_INTERNAL_ERROR;
  }
  moqtrun_upd_resched(hub, p, s, t);
  moqtss_on_update(hub, s, params, t); /* SSTS: joins once applied */
  return MOQTRUN_REQ_ACCEPT;
}

/* The REQUEST_ERROR code for the update, or MOQTRUN_REQ_ACCEPT once it is
 * applied. The concurrent Range Filter total is vetted first (10.4):
 * refused before anything is applied. */
static u64 moqtrun_upd_verdict(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  if (!s) {
    return MOQCTL_ERR_DOES_NOT_EXIST;
  }
  if (moqtrun_rngf_over(s, params)) {
    return MOQCTL_ERR_INVALID_FILTER;
  }
  return moqtrun_upd_checked(hub, p, s, t, params);
}

/* The updated state is also what a returning publisher re-attaches
 * (moqtrun_reattach_one_sub; only the subscriber changes it, 5.1). */
void moqtrun_upd_remember(wired_moqtrun_peer* p, const wired_moqtrun_sub* s) {
  wired_moqtrun_sub* kept = moqtrun_sub_state_by_rid(p, s->request_id);
  if (kept && kept != s) {
    *kept = *s;
  }
}

static void moqtrun_update_sub_apply(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_sub*   s,
    wired_moqtrun_track* t,
    const moqctl_params* params,
    u64                  rid) {
  u64 code = moqtrun_upd_verdict(hub, p, s, t, params);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    if (s) {
      moqtrun_sub_done(hub, p, p->req, t, s, MOQCTL_DONE_UPDATE_FAILED);
    }
    return;
  }
  /* SWITCH_FROM (moqtswitch.c): activate s; re-bound a re-filtered s */
  moqtsw_begin(hub, moqtrun_sw_ops(), t, s, params);
  moqtsw_rebound(s);
  moqtrun_upd_remember(p, s);
  moqtrun_queue_request_ok(p, t);
  moqtrun_ngr_relay(hub, t, params);
  moqtrun_fill_on_update(hub, p, t, s, params, rid);
}

/* SWITCH_FROM (moqtswitch.c) on a REQUEST_UPDATE: an invalid switch is
 * refused INVALID_SWITCH before anything is applied and -- unlike a
 * failed parameter update -- leaves the subscription as it was. */
static int moqtrun_upd_sw_refused(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    usz                        idx,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  u64 code = moqtsw_upd_check(hub, moqtrun_sw_ops(), idx, s, t, params);
  if (code == MOQTSW_ACCEPT) {
    return 0;
  }
  moqtrun_send_request_error(p, code);
  return 1;
}

void moqtrun_update_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    usz                  idx,
    const moqctl_params* params,
    u64                  rid) {
  moqtrun_rdv_settle_early(hub, p);
  wired_moqtrun_track* t = 0;
  wired_moqtrun_sub*   s = moqtrun_upd_target(hub, p, idx, &t);
  if (moqtrun_upd_sw_refused(hub, p, idx, s, t, params)) {
    return;
  }
  moqtrun_update_sub_apply(hub, p, s, t, params, rid);
}

/* A namespace-scoped request: PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE or
 * SUBSCRIBE_TRACKS (draft-22 9.5 updates all three alike). */
int moqtrun_kind_is_ns(u64 kind) {
  return kind == MOQNS_T_PUBLISH_NAMESPACE ||
         kind == MOQNS_T_SUBSCRIBE_NAMESPACE ||
         kind == MOQCTL_T_SUBSCRIBE_TRACKS;
}
