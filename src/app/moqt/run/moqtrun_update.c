#include "app/moqt/run/moqtrun_impl.h"

/* The subscription a REQUEST_UPDATE on p's request stream targets
 * (moqtrun_upd_target): peer slot idx, s, and its track t (0 while s
 * waits for a new path). */
typedef struct {
  usz                  idx;
  wired_moqtrun_sub*   s;
  wired_moqtrun_track* t;
} moqtrun_upd_at;

static u64 moqtrun_upd_verdict(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params);
static u64 moqtrun_upd_checked(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params);
static void moqtrun_upd_failed(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    u64                   code);
static void moqtrun_update_sub_apply(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params,
    u64                   rid);
static int moqtrun_upd_sw_refused(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params);

/* The REQUEST_ERROR code for the update, or MOQTRUN_REQ_ACCEPT; nothing
 * is applied yet. The concurrent Range Filter total is vetted first
 * (10.4); parameters are refused as on SUBSCRIBE (moqtrun_params_refusal). */
static u64 moqtrun_upd_verdict(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params) {
  if (!u->s) {
    return MOQCTL_ERR_DOES_NOT_EXIST;
  }
  if (moqtrun_rngf_over(u->s, params)) {
    return MOQCTL_ERR_INVALID_FILTER;
  }
  return moqtss_upd_check( /* SSTS (moqtssts_run.c) */
      hub, u->s, params, moqtrun_ssts_settable(hub, p, u->t),
      moqtrun_params_refusal(params));
}

/* Applies an accepted update: INTERNAL_ERROR when it cannot stand
 * (moqtrun_upd_apply restored s), else MOQTRUN_REQ_ACCEPT. */
static u64 moqtrun_upd_checked(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params) {
  if (!moqtrun_upd_apply(hub, p, u->s, u->t, params)) {
    return MOQCTL_ERR_INTERNAL_ERROR;
  }
  moqtrun_upd_resched(hub, p, u->s, u->t);
  moqtss_on_update(hub, u->s, params, u->t); /* SSTS: joins once applied */
  return MOQTRUN_REQ_ACCEPT;
}

/* The updated state is also what a returning publisher re-attaches
 * (moqtrun_reattach_one_sub; only the subscriber changes it, 5.1). */
void moqtrun_upd_remember(wired_moqtrun_peer* p, const wired_moqtrun_sub* s) {
  wired_moqtrun_sub* kept = moqtrun_sub_state_by_rid(p, s->request_id);
  if (kept && kept != s) {
    *kept = *s;
  }
}

/* A refused update: REQUEST_ERROR code, and an existing subscription
 * ends UPDATE_FAILED with its mirrors. */
static void moqtrun_upd_failed(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    u64                   code) {
  moqtrun_send_request_error(p, code);
  if (u->s) {
    moqtrun_sub_done(hub, p, p->req, u->t, u->s, MOQCTL_DONE_UPDATE_FAILED);
    moqtrun_cancel_peer_subs(
        hub, u->s->session_idx, u->s->request_id); /* mirrors */
  }
}

static void moqtrun_update_sub_apply(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params,
    u64                   rid) {
  u64 code = moqtrun_upd_verdict(hub, p, u, params);
  if (code == MOQTRUN_REQ_ACCEPT) {
    code = moqtrun_upd_checked(hub, p, u, params);
  }
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_upd_failed(hub, p, u, code);
    return;
  }
  /* SWITCH_FROM (moqtswitch.c): activate s; re-bound a re-filtered s */
  moqtsw_begin(hub, moqtrun_sw_ops(), u->t, u->s, params);
  moqtsw_rebound(u->s);
  moqtrun_upd_remember(p, u->s);
  moqtrun_mirror_update(hub, p, u->s, params);
  moqtrun_queue_request_ok(p, u->t);
  moqtrun_ngr_relay(hub, u->t, params);
  moqtrun_pub_resume(hub, u->t);
  moqtrun_fill_on_update(hub, p, u->t, u->s, params, rid);
}

/* SWITCH_FROM (moqtswitch.c) on a REQUEST_UPDATE: an invalid switch is
 * refused INVALID_SWITCH before anything is applied and -- unlike a
 * failed parameter update -- leaves the subscription as it was. */
static int moqtrun_upd_sw_refused(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    const moqtrun_upd_at* u,
    const moqctl_params*  params) {
  u64 code =
      moqtsw_upd_check(hub, moqtrun_sw_ops(), u->idx, u->s, u->t, params);
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
  moqtrun_upd_at u = {idx, 0, 0};
  u.s              = moqtrun_upd_target(hub, p, idx, &u.t);
  if (moqtrun_upd_sw_refused(hub, p, &u, params)) {
    return;
  }
  moqtrun_update_sub_apply(hub, p, &u, params, rid);
}

/* A namespace-scoped request: PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE or
 * SUBSCRIBE_TRACKS (draft-22 9.5 updates all three alike). */
int moqtrun_kind_is_ns(u64 kind) {
  return kind == MOQNS_T_PUBLISH_NAMESPACE ||
         kind == MOQNS_T_SUBSCRIBE_NAMESPACE ||
         kind == MOQCTL_T_SUBSCRIBE_TRACKS;
}
