#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_wt_notify(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, wired_span protocol);
static u64  srvrun_wt_streams_seed_cap(const u64* v);
static void srvrun_wt_latches_clear(srvrun_conn* c, int sidx);
static void srvrun_wt_session_open(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx);
static void srvrun_wt_capsule_arm(srvrun_conn* c, int sidx);

/* Notify the app that session slot sidx was established (its 2xx has been
 * built), with the recorded :path and the negotiated subprotocol (empty when
 * none). No-op without a registered callback. */
static void srvrun_wt_notify(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, wired_span protocol) {
  if (!cfg->wt_on_session) return;
  cfg->wt_on_session(
      cfg->wt_session_ctx, srvrun_wt_slot(c, sidx),
      wired_span_of(c->wt_path[sidx], c->wt_path_len[sidx]), protocol);
}

/* Interop deviation from SS5.5.1/5.5.2 (proxygen clients -- moxygen, moqx --
 * send SETTINGS_WT_INITIAL_MAX_DATA alone and never a WT_MAX_STREAMS
 * capsule, so the spec default of 0 would block this server's own SETUP
 * stream forever): a peer that declared only a data limit gets the stream
 * ceiling. Returns the value OR-ed into both stream limits. */
static u64 srvrun_wt_streams_seed_cap(const u64* v) {
  return (u64)(v[2] != 0 && v[0] == 0 && v[1] == 0) * WTSESSION_STREAMS_MAX;
}

/* draft-ietf-webtrans-http3-16 SS5.5.1-5.5.3: seed a new session's limits
 * from the client's SETTINGS_WT_INITIAL_* (the "previously received" baseline
 * for SS5.6.2/5.6.4). The SETTINGS are final by now: SS3.1 holds every
 * CONNECT until they arrive (srvrun_wt_settings_ready) and RFC 9114 7.2.4
 * allows only one. SS5.1: flow control is enabled when both sides sent a
 * non-zero one; this server always does (control_settings.c), so the peer
 * decides. A stream value past 2^60 is clamped to it (SS5.6.2's ceiling). */
void srvrun_wt_seed_limits(const srvrun_conn* c, wired_wt_session* s) {
  const u64* v    = c->l.peer_wt_initial;
  u64        cap  = srvrun_wt_streams_seed_cap(v);
  s->flow_control = (v[0] | v[1] | v[2]) != 0;
  wired_wt_session_set_max_streams(
      s, 0, u64_min(v[0] | cap, WTSESSION_STREAMS_MAX));
  wired_wt_session_set_max_streams(
      s, 1, u64_min(v[1] | cap, WTSESSION_STREAMS_MAX));
  wired_wt_session_set_max_data(s, v[2]);
}

/* A session slot's app-latched close/drain belong to the session that
 * latched them: a fresh session in the slot starts with none (and no stale
 * close code or message from the slot's previous occupant). */
static void srvrun_wt_latches_clear(srvrun_conn* c, int sidx) {
  c->wt_close_pending[sidx] = 0;
  c->wt_close_code[sidx]    = 0;
  c->wt_close_msg_len[sidx] = 0;
  c->wt_drain_pending[sidx] = 0;
}

/* Bring session slot sidx up for the CONNECT on c->l.req_stream_id: init,
 * seed its limits, establish it, mark it active and count it. */
static void srvrun_wt_session_open(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx) {
  wired_wt_session_init(srvrun_wt_slot(c, sidx), c->l.req_stream_id);
  srvrun_wt_seed_limits(c, srvrun_wt_slot(c, sidx));
  wired_wt_session_establish(srvrun_wt_slot(c, sidx));
  (*srvrun_wt_active_slot(c, sidx)) = 1;
  c->wt_sess_window_count++;
  cfg->env->wt_usage.sessions++;
  srvrun_wt_record_path(c, sidx);
}

/* Start session sidx's capsule receive state fresh. */
static void srvrun_wt_capsule_arm(srvrun_conn* c, int sidx) {
  /* wt_capsule_rx_at's own doc: the peer's capsule bytes start right after
   * its request HEADERS frame on this same stream (RFC 9297 SS3.2). */
  c->wt_capsule_rx_at[sidx] = srvrun_wt_capsule_start(c);
  c->wt_capq[sidx].n        = 0;
  c->wt_capq[sidx].skip     = 0;
  c->wt_drain_rcvd[sidx]    = 0;
  srvrun_wt_latches_clear(c, sidx);
}

/* Establish a WebTransport session for this Extended CONNECT (draft-ietf-
 * webtrans-http3-15 SS3.2/SS4) in the first free session slot: the session id
 * is the CONNECT stream's own id. The 200 carries a wt-protocol header when
 * a subprotocol was negotiated (SS3.4), and the app's wt_on_session callback
 * (if any) fires once after it is built. Skips the normal app-handler
 * response path entirely. Caller (srvrun_dispatch_wt_free_slot) already
 * confirmed a free slot exists. */
void srvrun_start_wt(
    const srvrun_cfg* cfg, int slot, srvrun_conn* c, srvrun_resp* r) {
  static const u8 name[] = {'w', 't', '-', 'p', 'r', 'o',
                            't', 'o', 'c', 'o', 'l'};
  srvrun_wt_proto p;
  qpack_field     f;
  int             sidx = srvrun_wt_free_slot(c);
  /* Caller (srvrun_dispatch_wt) already confirmed a free slot exists right
   * before reaching here with nothing in between that could claim one, so
   * this never actually fires -- guarding it anyway keeps wt_path/wt_path_len
   * (SRVRUN_MAX_WT_SESSIONS-sized) indexed only by a value in range. */
  if (sidx < 0) return;
  srvrun_wt_proto_pick(cfg, c, &p);
  f = (qpack_field){
      wired_span_of(name, sizeof name), wired_span_of(p.sfv, p.sfv_len)};
  srvrun_wt_session_open(cfg, c, sidx);
  srvrun_start_wt_status(cfg->env, slot, c, r, 200, p.sfv_len ? &f : 0);
  /* wt_connect_sent_len's own doc: the 2xx HEADERS frame's byte length is
   * where a later capsule append (srvrun_send_wt_capsule) must continue. */
  c->wt_connect_sent_len[sidx] = r->sess.q.len;
  srvrun_wt_capsule_arm(c, sidx);
  srvrun_wt_notify(cfg, c, sidx, wired_span_of(p.tok, p.tok_len));
}
