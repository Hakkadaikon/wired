#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_datagram_request_type_ok(const wired_wt_session* s);
static int srvrun_dg_send_ready(const srvrun_conn* c);
static int srvrun_dgring_target_ok(
    const wired_srvrun_env* env, int slot, const wired_wt_session* s);
static srvrun_dgring_entry* srvrun_dgring_tail(wired_srvrun_env* env);
static usz srvrun_dg_prefix_put(u8* buf, usz cap, int raw, u64 connect_id);
static int srvrun_dgring_fill(
    srvrun_dgring_entry* e,
    int                  conn_slot,
    int                  raw,
    u64                  connect_id,
    wired_span           payload);
static int srvrun_dgring_push(
    wired_srvrun_env* env, int slot, u64 connect_id, wired_span payload);
static int srvrun_bcast_ring_target(wired_srvrun_env* env, int cslot, int i);

int wired_server_wt_stream_stop(
    wired_wt_session* s, u64 stream_id, u32 error_code) {
  srvrun_conn* c = srvrun_session_conn(s);
  usz          i;
  if (srvrun_wt_stop_refused(
          c, srvrun_wt_session_slot_or_absent(c, s), stream_id)) {
    return 0;
  }
  i                              = c->wt_stream_reset_n++;
  c->wt_stream_reset_id[i]       = stream_id;
  c->wt_stream_reset_app_code[i] = error_code;
  c->wt_stream_reset_final[i]    = 0;
  c->wt_stream_reset_stop[i]     = 1;
  c->wt_stream_reset_sid[i]      = SRVRUN_WT_NO_SID;
  return 1;
}

/* RFC 9297 2 (9297-001): "HTTP Datagrams MUST only be sent with an
 * association to an HTTP request that explicitly supports them." The only
 * request type this SDK associates HTTP Datagrams with is a WebTransport
 * CONNECT (draft-ietf-webtrans-http3-15 SS4.2/SS4.3): wired_server_wt_
 * send_datagram_to's own parameter type (wired_wt_session*) already makes
 * that request-type association a compile-time constraint -- a GET/POST
 * response (srvrun_resp) has no wired_wt_session to pass, so no caller can
 * even attempt to send an HTTP Datagram for a request type that does not
 * support them. This predicate names that gate explicitly (rather than
 * leaving it implicit in the parameter type alone) and adds the one runtime
 * half the type system cannot express: the session's own state must have
 * actually reached ESTABLISHED/DRAINING (the server sent its 2xx, so the
 * association is live), not merely UNESTABLISHED/CLOSED. */
static int srvrun_wt_datagram_request_type_ok(const wired_wt_session* s) {
  return srvrun_wt_session_send_side_open(s);
}

/* RFC 9297 2.1: an HTTP/3 connection sends no DATAGRAM before its own
 * SETTINGS; a raw-QUIC one has no SETTINGS (RFC 9221 alone applies, the
 * peer's max_datagram_frame_size is checked at send time). */
static int srvrun_dg_send_ready(const srvrun_conn* c) {
  return c->l.h3.settings_sent || srvrun_conn_is_raw(c);
}

/* slot names a live connection whose own SETTINGS have been sent (RFC 9297
 * 2.1's ordering rule, same gate as srvrun_queue_datagram), AND s passes
 * the RFC 9297 2 / 9297-001 request-type gate above (which also folds in
 * 9297-007's send-side-open check, ESTABLISHED or DRAINING only). */
static int srvrun_dgring_target_ok(
    const wired_srvrun_env* env, int slot, const wired_wt_session* s) {
  return slot >= 0 && srvrun_dg_send_ready(&env->conns[slot]) &&
         srvrun_wt_datagram_request_type_ok(s);
}

/* The next free ring entry (FIFO tail), or 0 when the ring is full. */
static srvrun_dgring_entry* srvrun_dgring_tail(wired_srvrun_env* env) {
  if (env->dgring_n >= SRVRUN_DGRING_CAP) {
    return 0;
  }
  return &env->dgring[(env->dgring_head + env->dgring_n) % SRVRUN_DGRING_CAP];
}

/* The DATAGRAM prefix for one session (rawq_dgram_prefix_len): the RFC 9297
 * 2.1 quarter-stream-id (connect_id / 4, wtwire_qsid_put) on WebTransport,
 * nothing on raw QUIC (draft-ietf-moq-transport-19 11.3). Its length, 0
 * for none. */
static usz srvrun_dg_prefix_put(u8* buf, usz cap, int raw, u64 connect_id) {
  if (!rawq_dgram_prefix_len(raw, connect_id)) {
    return 0;
  }
  return wtwire_qsid_put(buf, cap, connect_id);
}

/* Fill e with the session's prefix (srvrun_dg_prefix_put) followed by the
 * payload copy. 0 when the prefix cannot be encoded or the prefixed
 * payload does not fit a ring slot. */
static int srvrun_dgring_fill(
    srvrun_dgring_entry* e,
    int                  conn_slot,
    int                  raw,
    u64                  connect_id,
    wired_span           payload) {
  usz qn = srvrun_dg_prefix_put(e->buf, sizeof e->buf, raw, connect_id);
  if (qn != rawq_dgram_prefix_len(raw, connect_id) ||
      payload.n > sizeof e->buf - qn) {
    return 0;
  }
  bytes_memcpy(e->buf + qn, payload.p, payload.n);
  e->len       = qn + payload.n;
  e->conn_slot = conn_slot;
  return 1;
}

static int srvrun_dgring_push(
    wired_srvrun_env* env, int slot, u64 connect_id, wired_span payload) {
  srvrun_dgring_entry* e   = srvrun_dgring_tail(env);
  int                  raw = srvrun_conn_is_raw(&env->conns[slot]);
  if (!e) {
    return 0;
  }
  if (!srvrun_dgring_fill(e, slot, raw, connect_id, payload)) {
    return 0;
  }
  e->conn_gen = env->conns[slot].gen;
  env->dgring_n++;
  return 1;
}

int wired_server_wt_send_datagram_to(wired_wt_session* s, wired_span payload) {
  wired_srvrun_env* env;
  int               slot;
  srvrun_session_conn_env(s, &env, &slot);
  if (!srvrun_dgring_target_ok(env, slot, s)) {
    return 0;
  }
  return srvrun_dgring_push(env, slot, s->connect_stream_id, payload);
}

/* Connection slot cslot's session slot i is an eligible ring-broadcast
 * target: the connection is up, the slot holds a session, and it passes the
 * same RFC 9297 gates a session-addressed send applies (SETTINGS sent,
 * association established, CONNECT send side open --
 * srvrun_dgring_target_ok). */
static int srvrun_bcast_ring_target(wired_srvrun_env* env, int cslot, int i) {
  srvrun_conn* c = &env->conns[cslot];
  return c->up && srvrun_wt_is_active(c, i) &&
         srvrun_dgring_target_ok(env, cslot, srvrun_wt_slot(c, i));
}

/* Queue data for one (connection, session) pair: an ineligible pair is
 * skipped (1 -- not a failure, mirroring srvrun_broadcast_to_all's own
 * best-effort skip), an eligible one that cannot be queued (ring full, or
 * the qsid-prefixed payload exceeds a ring slot) reports 0. */
int srvrun_bcast_ring_sess(
    wired_srvrun_env* env, int cslot, int i, wired_span data) {
  if (!srvrun_bcast_ring_target(env, cslot, i)) {
    return 1;
  }
  return srvrun_dgring_push(
      env, cslot, srvrun_wt_slot(&env->conns[cslot], i)->connect_stream_id,
      data);
}
