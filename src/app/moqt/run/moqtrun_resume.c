#include "app/moqt/run/moqtrun_impl.h"

/* ===== requests waiting for an unpaused upstream (draft-23 7.5) =====
 * "a relay MUST only compute the Largest Object from an upstream
 * subscription that is currently unpaused ... If such an upstream
 * subscription does not exist, the relay MUST ... unpause an upstream
 * subscription ... and use the resulting LARGEST_OBJECT parameter." A
 * SUBSCRIBE or TRACK_STATUS for a track whose PUBLISH is paused, or whose
 * unpause is not answered yet, waits in a rendezvous slot; the
 * REQUEST_UPDATE_OK (its Largest counted, moqtrun_largest_note) re-runs it
 * the normal found-track way, a refusal or the PUBLISH's end answers it
 * REQUEST_ERROR. A silent publisher holds the slot WIRED_MOQTRUN_UP_WAIT_MS
 * at most (then TIMEOUT), bounded by WIRED_MOQTRUN_MAX_RDV and
 * WIRED_MOQTRUN_RDV_PER_SESSION (a request past them is refused
 * EXCESSIVE_LOAD at once). */

static int moqtrun_must_wait(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t);
static int  moqtrun_resume_of(const wired_moqtrun_rdv* r, moqtrun_key k);
static int  moqtrun_resume_due(const wired_moqtrun_track* t);
static void moqtrun_resume_end(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqtrun_rdv_fn fn, u64 code);
static void moqtrun_resume_settle(
    wired_moqt_hub* hub, wired_moqtrun_track* t, u64 code);

static int moqtrun_must_wait(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  return moqtrun_relay_largest(p->ver) && p->req && !moqtrun_track_usable(t);
}

/* 1 when p's request (body, on p->req) for t waits for t's unpause --
 * held, or refused EXCESSIVE_LOAD with no slot left -- instead of being
 * answered now. */
int moqtrun_resume_wait(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* t,
    wired_span           body) {
  if (!moqtrun_must_wait(p, t)) {
    return 0;
  }
  if (moqtrun_rdv_wait(hub, p, t, body)) {
    moqtrun_pub_resume(hub, t);
  }
  return 1;
}

static int moqtrun_resume_of(const wired_moqtrun_rdv* r, moqtrun_key k) {
  return r->resume && moqtrun_rdv_matches(r, k);
}

/* Some request waits for t's unpause. */
int moqtrun_resume_waiting(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  moqtrun_key k = moqtrun_track_key(t);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_resume_of(&hub->rdv[i], k)) {
      return 1;
    }
  }
  return 0;
}

/* Every request waiting for t is answered by fn (moqtrun_rdv_answer). */
static void moqtrun_resume_end(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqtrun_rdv_fn fn, u64 code) {
  moqtrun_key k = moqtrun_track_key(t);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_resume_of(&hub->rdv[i], k)) {
      moqtrun_rdv_answer(hub, &hub->rdv[i], fn, t, code);
    }
  }
}

/* t has an unpause outstanding. */
static int moqtrun_resume_due(const wired_moqtrun_track* t) {
  return t && t->resume_in;
}

/* One of the hub's REQUEST_UPDATEs on p's PUBLISH stream was answered
 * (code MOQTRUN_REQ_ACCEPT for REQUEST_OK, else the REQUEST_ERROR's).
 * The unpause's own answer ends the waits: a refused one leaves the
 * PUBLISH paused, so a later request unpauses again. */
void moqtrun_pub_answered(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 code) {
  wired_moqtrun_track* t = moqtrun_pubdone_track_of(p, p->req->request_id);
  if (!moqtrun_resume_due(t)) {
    return;
  }
  t->resume_in--;
  if (!t->resume_in) {
    moqtrun_resume_settle(hub, t, code);
  }
}

/* The unpause on t's PUBLISH answered code: its waiters re-run on
 * REQUEST_OK; on REQUEST_ERROR they get its code and t stays paused, on
 * every draft (9.5: a refused REQUEST_UPDATE changes nothing). */
static void moqtrun_resume_settle(
    wired_moqt_hub* hub, wired_moqtrun_track* t, u64 code) {
  int ok        = code == MOQTRUN_REQ_ACCEPT;
  t->pub_paused = (u8)!ok;
  moqtrun_resume_end(
      hub, t, ok ? moqtrun_rdv_do_resume : moqtrun_rdv_do_refuse, code);
}

/* t's PUBLISH ended (PUBLISH_DONE, cancel, its session's loss): its
 * waiters are refused INTERNAL_ERROR -- the hub never answers OK from a
 * subscription that is gone. */
void moqtrun_resume_gone(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  moqtrun_resume_end(hub, t, moqtrun_rdv_do_refuse, MOQCTL_ERR_INTERNAL_ERROR);
}

/* A waiter re-runs once t is usable: TRACK_STATUS, or the SUBSCRIBE
 * (moqtrun_rdv_do_resolve). */
void moqtrun_rdv_do_resume(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code) {
  if (sp->req->kind == MOQTSTAT_T_TRACK_STATUS) {
    moqtrun_tstat_answer(hub, sp, wired_span_of(r->body, r->body_len));
    return;
  }
  moqtrun_rdv_do_resolve(hub, sp, r, t, code);
}
