#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_up_send(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    moqtrun_key         k);
static int moqtrun_up_open(
    wired_moqt_hub* hub, const wired_moqtrun_req* a, moqtrun_key k);
static int  moqtrun_rdv_fresh(const wired_moqtrun_rdv* r, moqtrun_key k);
static void moqtrun_up_unserved(
    wired_moqt_hub* hub, wired_moqtrun_rdv* r, const wired_moqtrun_req* a);
static int moqtrun_up_needs(wired_moqt_hub* hub, const wired_moqtrun_rdv* r);

/* SUBSCRIBE for k on a fresh request stream to pp (the hub's next odd
 * Request ID, draft-18 10.1). No parameters: FORWARD defaults to 1 (9.5
 * "MUST use Forward=1 when subscribing upstream" for a Forward=1
 * subscriber) and no filter is unfiltered; each downstream filter is
 * applied by the relay gates. The QUIC stream limit is the only request
 * limit (draft-18 removed MAX_REQUEST_ID): no stream, no SUBSCRIBE. */
static int moqtrun_up_send(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    moqtrun_key         k) {
  u8
                   msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS +
                       WIRED_MOQTRUN_MAX_NAME + 16];
  moqctl_subscribe m   = {0};
  usz              off = 0;
  usz              n;
  i64              sid;
  m.request_id = pp->request_id_next;
  m.name.name  = k.name;
  moqctl_ns_take(k.ns, &off, &m.name.ns);
  n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_SUBSCRIBE,
      moqtrun_up_encode_sub, &m);
  sid = hub->io.open_bidi_stream(pp->wt, wired_span_of(msg, n));
  if (sid < 0) return 0;
  pp->request_id_next += 2;
  moqtrun_up_store(u, pp->wt, (u64)sid, m.request_id, k);
  moqtrun_rp_mark(hub, k, pp->wt);
  return 1;
}

/* 1 when an upstream SUBSCRIBE for k went to a's session. */
static int moqtrun_up_open(
    wired_moqt_hub* hub, const wired_moqtrun_req* a, moqtrun_key k) {
  wired_moqtrun_up* u = a ? moqtrun_up_free_slot(hub) : 0;
  if (!u) return 0;
  return moqtrun_up_send(hub, moqtrun_find_by_wt(hub, a->wt), u, k);
}

/* ----- the waiters ----- */

/* A SUBSCRIBE waiting for k, not yet answered (a wait for a new path
 * was). */
static int moqtrun_rdv_fresh(const wired_moqtrun_rdv* r, moqtrun_key k) {
  return moqtrun_rdv_matches(r, k) && !r->repath;
}

/* Every SUBSCRIBE waiting for k is answered REQUEST_ERROR code; a wait
 * for a new path keeps waiting. */
void moqtrun_up_refuse_waiters(wired_moqt_hub* hub, moqtrun_key k, u64 code) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    if (moqtrun_rdv_fresh(&hub->rdv[i], k))
      moqtrun_rdv_answer(hub, &hub->rdv[i], moqtrun_rdv_do_refuse, 0, code);
}

int moqtrun_up_waiters(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    if (moqtrun_rdv_matches(&hub->rdv[i], k)) return 1;
  return 0;
}

/* A waiter no upstream can serve: with no announcer left DOES_NOT_EXIST
 * (10.2.6's answer for no publisher), with no stream to open toward it
 * EXCESSIVE_LOAD. A rendezvous hold keeps waiting for its deadline. */
static void moqtrun_up_unserved(
    wired_moqt_hub* hub, wired_moqtrun_rdv* r, const wired_moqtrun_req* a) {
  if (!r->up_only) return;
  moqtrun_rdv_answer(
      hub, r, moqtrun_rdv_do_refuse, 0,
      a ? MOQCTL_ERR_EXCESSIVE_LOAD : MOQCTL_ERR_DOES_NOT_EXIST);
}

/* 1 iff r waits with no upstream SUBSCRIBE for its track. */
static int moqtrun_up_needs(wired_moqt_hub* hub, const wired_moqtrun_rdv* r) {
  return r->in_use && !moqtrun_up_of_key(hub, moqtrun_up_rdv_key(r));
}

void moqtrun_up_wait_one(wired_moqt_hub* hub, wired_moqtrun_rdv* r) {
  moqtrun_key        k = moqtrun_up_rdv_key(r);
  wired_moqtrun_req* a;
  if (!moqtrun_up_needs(hub, r)) return;
  a = moqtrun_up_announcer(hub, r->wt, k);
  if (!moqtrun_up_open(hub, a, k)) moqtrun_up_unserved(hub, r, a);
}

/* ----- ending an upstream subscription ----- */

/* Cancels the hub's request (draft-19 3.3.3, draft-22 6.4.2.3:
 * RESET_STREAM and STOP_SENDING). */
void moqtrun_up_reset(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_up* u) {
  hub->io.stream_reset(u->wt, u->stream_id, MOQTRUN_RESET_CANCELLED);
  moqtrun_stream_stop(hub, pp, u->stream_id, MOQTRUN_RESET_CANCELLED);
}
