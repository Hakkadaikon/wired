#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_up_candidate(
    wired_moqt_hub*          hub,
    const wired_moqtrun_req* q,
    const wired_wt_session*  s,
    moqtrun_key              k,
    u64                      skip);
static wired_moqtrun_req* moqtrun_up_announcer_skip(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k, u64 skip);

void moqtrun_drain_tick(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_drain_due(&hub->peers[i], now_ms)) {
      moqtrun_drain_expire(hub, &hub->peers[i], now_ms);
    }
    moqtrun_ctl_retry(hub, &hub->peers[i]);
    moqtrun_hold_replay(hub, &hub->peers[i]);
  }
}

int wired_moqt_goaway(wired_moqt_hub* hub, wired_span new_uri, u64 timeout_ms) {
  if (new_uri.n > WIRED_MOQTRUN_GOAWAY_URI_MAX) {
    return -1;
  }
  return moqtrun_goaway_send(hub, 0, new_uri, timeout_ms);
}

/* A peer draining its session is answered with the hub's GOAWAY and, as
 * if it had sent one, is asked nothing new (moqtrun_up_peer_usable). */
void wired_moqt_on_session_draining(void* app_ctx, wired_wt_session* s) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (p) {
    p->wt_drained = 1;
  }
  moqtrun_goaway_send(
      hub, s, wired_span_of(0, 0), WIRED_MOQTRUN_DRAIN_TIMEOUT_MS);
}

/* ======= upstream SUBSCRIBE (draft-18/19 9.4-9.5, draft-22 7.4/7.6) =======
 * A SUBSCRIBE that misses every PUBLISHed track but whose namespace a
 * session announced (PUBLISH_NAMESPACE, prefix match) waits in hub->rdv
 * while the hub, as a subscriber, sends its own SUBSCRIBE to that
 * publisher on a request stream it opens (hub->ups). Its SUBSCRIBE_OK
 * claims a track slot on the publisher exactly as a PUBLISH would, and
 * every waiter resolves through moqtrun_rdv_resolve -- so no downstream
 * SUBSCRIBE_OK precedes the Established upstream subscription (9.4 MUST),
 * and the relay, alias, PUBLISH_DONE and session-close paths all apply
 * unchanged. One upstream subscription per Full Track Name serves every
 * downstream subscriber (9.4 MAY aggregate). moqtrun_up_sync, at the end
 * of every dispatch and tick, is the one decision point (UpstreamSub.tla
 * Sweep): it cancels an upstream nobody wants any more and sends one for
 * a waiter that has none.
 * ponytail: one announcer per name (9.5 says "each publisher"; the hub
 * keys one track per name); a publisher's RESET of the hub's stream is
 * left to the session's end. */

moqtrun_key moqtrun_up_key(const wired_moqtrun_up* u) {
  moqtrun_key k;
  k.ns   = wired_span_of(u->ns, u->ns_len);
  k.name = wired_span_of(u->name, u->name_len);
  return k;
}

moqtrun_key moqtrun_up_rdv_key(const wired_moqtrun_rdv* r) {
  moqtrun_key k;
  k.ns   = wired_span_of(r->ns, r->ns_len);
  k.name = wired_span_of(r->name, r->name_len);
  return k;
}

/* 1 iff q is a live PUBLISH_NAMESPACE of a session other than s whose
 * namespace is a field prefix of k's (9.5 Namespace Prefix Matching; a
 * session's own announcement never serves its own SUBSCRIBE). */
int moqtrun_up_covers(
    const wired_moqtrun_req* q, const wired_wt_session* s, moqtrun_key k) {
  u64 n;
  return moqtrun_disc_is(q, MOQNS_T_PUBLISH_NAMESPACE) && q->wt != s &&
         moqtrun_disc_starts(
             moqtrun_disc_fields(q, &n), moqtrun_disc_fields_of(k.ns, &n));
}

/* A session announcing anew (q) is worth asking again by every wait for
 * a track q's namespace covers. */
void moqtrun_rp_untry(wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  u64 bit = moqtrun_rp_bit(hub, q->wt);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_up_covers(q, 0, moqtrun_up_rdv_key(&hub->rdv[i]))) {
      hub->rdv[i].tried &= ~bit;
    }
  }
}

/* p may be sent a new request: connected, not being closed by the hub
 * (nothing more goes to it, moqtrun_rdv_target), and p sent no GOAWAY
 * nor drained its session (draft-22 9.2: the receiver SHOULD NOT
 * initiate new requests; the hub's own GOAWAY does not stop it, the
 * re-paths of a drain need it). */
int moqtrun_up_peer_usable(const wired_moqtrun_peer* p) {
  return moqtrun_rdv_peer_open(p) && !p->sess.goaway_recv && !p->wt_drained;
}

/* q may be asked: it covers k, its session not skipped and usable. */
static int moqtrun_up_candidate(
    wired_moqt_hub*          hub,
    const wired_moqtrun_req* q,
    const wired_wt_session*  s,
    moqtrun_key              k,
    u64                      skip) {
  return moqtrun_up_covers(q, s, k) && !(skip & moqtrun_rp_bit(hub, q->wt)) &&
         moqtrun_up_peer_usable(moqtrun_find_by_wt(hub, q->wt));
}

static wired_moqtrun_req* moqtrun_up_announcer_skip(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k, u64 skip) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_up_candidate(hub, &hub->reqs[i], s, k, skip)) {
      return &hub->reqs[i];
    }
  }
  return 0;
}

/* Skips the sessions a wait for a new path must not ask
 * (moqtrun_rp_skip), and prefers one no wait for k belongs to: a waiting
 * session's own path cannot re-attach that waiter (moqtrun_rp_waiters). */
wired_moqtrun_req* moqtrun_up_announcer(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k) {
  u64                skip = moqtrun_rp_skip(hub, k);
  wired_moqtrun_req* a =
      moqtrun_up_announcer_skip(hub, s, k, skip | moqtrun_rp_waiters(hub, k));
  return a ? a : moqtrun_up_announcer_skip(hub, s, k, skip);
}
