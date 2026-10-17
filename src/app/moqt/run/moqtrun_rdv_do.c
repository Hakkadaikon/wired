#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_rdv_do_resolve(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code);
static int moqtrun_rdv_own_up(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, wired_moqtrun_track* t);
static void moqtrun_rdv_own_refuse(wired_moqt_hub* hub, wired_moqtrun_rdv* r);
static void moqtrun_rdv_resolve_one(
    wired_moqt_hub* hub, wired_moqtrun_rdv* r, wired_moqtrun_track* t);
static int moqtrun_rdv_due(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, u64 now_ms);
static moqtrun_rdv_fn moqtrun_rdv_expiry(const wired_moqtrun_rdv* r);

/* Ends hold r: answered by fn on its own stream, or -- the target gone
 * (TLA+ Cancel) -- silently. The slot frees either way, before fn runs,
 * so the answer is the hold's one and only (AtMostOneAnswer). */
void moqtrun_rdv_answer(
    wired_moqt_hub*      hub,
    wired_moqtrun_rdv*   r,
    moqtrun_rdv_fn       fn,
    wired_moqtrun_track* t,
    u64                  code) {
  wired_moqtrun_peer* sp;
  wired_moqtrun_req*  q = moqtrun_rdv_target(hub, r, &sp);
  r->in_use             = 0;
  if (!q) return;
  wired_moqtrun_req* saved = sp->req;
  sp->req                  = q;
  q->rdv_held              = 0;
  fn(hub, sp, r, t, code);
  sp->req = saved;
}

/* The held SUBSCRIBE, re-decoded in its session's draft, goes the normal
 * found-track way (moqtrun_subscribe_peer_track: SUBSCRIBE_OK, or the
 * held-subscription re-answer, or DOES_NOT_EXIST once subs[] is full). */
static void moqtrun_rdv_do_resolve(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code) {
  u8               ns_buf[WIRED_MOQTRUN_MAX_NS];
  usz              off = 0;
  moqctl_subscribe m;
  wired_span       body = wired_span_of(r->body, r->body_len);
  (void)code;
  if (moqctl_subscribe_take(sp->ver, body, &off, &m) != MOQCTL_OK) {
    moqtrun_send_request_error(sp, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_subscribe_peer_track(
      hub, sp, t, (usz)(sp - hub->peers), moqtrun_key_of(&m.name, ns_buf), &m);
}

/* REQUEST_ERROR code (22: SUBSCRIBE_ERROR, the same message): TIMEOUT
 * when no publisher came within the timeout (10.2.6), or the upstream's
 * refusal (moqtrun_up_refuse_waiters). */
void moqtrun_rdv_do_refuse(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code) {
  (void)hub;
  (void)r;
  (void)t;
  moqtrun_send_request_error(sp, code);
}

/* t came by the hub's upstream SUBSCRIBE to fresh hold r's own session:
 * never r's answer (its own announcement never serves it), r keeps
 * waiting. A wait for a new path is answered there anyway
 * (moqtrun_rp_do_relinked). */
static int moqtrun_rdv_own_up(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, wired_moqtrun_track* t) {
  const wired_moqtrun_up* u = moqtrun_up_of_track(hub, t);
  return !r->repath && u && u->wt == r->wt;
}

/* Fresh hold r met its own session's track: a hold with a deadline keeps
 * waiting for another path until then; one without (it waits only for an
 * upstream SUBSCRIBE) has nothing left to wait for, and would otherwise
 * keep that upstream alive forever. */
static void moqtrun_rdv_own_refuse(wired_moqt_hub* hub, wired_moqtrun_rdv* r) {
  if (r->up_only)
    moqtrun_rdv_answer(
        hub, r, moqtrun_rdv_do_refuse, 0, MOQCTL_ERR_DOES_NOT_EXIST);
}

static void moqtrun_rdv_resolve_one(
    wired_moqt_hub* hub, wired_moqtrun_rdv* r, wired_moqtrun_track* t) {
  if (moqtrun_rdv_own_up(hub, r, t)) {
    moqtrun_rdv_own_refuse(hub, r);
    return;
  }
  moqtrun_rdv_answer(
      hub, r, r->repath ? moqtrun_rp_do_relinked : moqtrun_rdv_do_resolve, t,
      0);
}

void moqtrun_rdv_resolve(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    if (moqtrun_rdv_matches(&hub->rdv[i], k))
      moqtrun_rdv_resolve_one(hub, &hub->rdv[i], t);
}

/* Past its deadline, or its target gone (swept without an answer). */
static int moqtrun_rdv_due(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, u64 now_ms) {
  wired_moqtrun_peer* sp;
  return r->in_use &&
         (now_ms >= r->deadline_ms || !moqtrun_rdv_target(hub, r, &sp));
}

static moqtrun_rdv_fn moqtrun_rdv_expiry(const wired_moqtrun_rdv* r) {
  return r->repath ? moqtrun_rp_do_done : moqtrun_rdv_do_refuse;
}

/* wired_moqt_tick's expiry pass, before its moqtrun_reqs_tick: that sends
 * each TIMEOUT or PUBLISH_DONE and FINs its stream, and its upstream sweep
 * then cancels an upstream SUBSCRIBE nobody waits for any more. */
void moqtrun_rdv_tick(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    if (moqtrun_rdv_due(hub, &hub->rdv[i], now_ms))
      moqtrun_rdv_answer(
          hub, &hub->rdv[i], moqtrun_rdv_expiry(&hub->rdv[i]), 0,
          MOQTRUN_ERR_TIMEOUT);
}
