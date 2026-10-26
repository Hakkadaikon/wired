#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_wt_shut_one(const srvrun_cfg* cfg, srvrun_conn* c, int i);
static int  srvrun_wt_shut_applies(const srvrun_conn* c);
static void srvrun_wt_shut_conn(const srvrun_cfg* cfg, srvrun_conn* c);
static void srvrun_wt_close_wait_drop(srvrun_conn* c, int i, u64 id);
static int  srvrun_wt_waits_any(const srvrun_conn* c);
static int  srvrun_conn_wt_waits(const srvrun_conn* c);

/* draft-ietf-webtrans-http3-16 6 (WTH3-081): close session slot i with
 * WT_CLOSE_SESSION (code 0, no message) and FIN on its CONNECT stream
 * (srvrun_send_wt_close), remembering that stream until the peer closes
 * it (wt_close_wait). */
static void srvrun_wt_shut_one(const srvrun_cfg* cfg, srvrun_conn* c, int i) {
  if (!srvrun_wt_is_active(c, i)) {
    return;
  }
  c->wt_close_code[i]    = 0;
  c->wt_close_msg_len[i] = 0;
  c->wt_close_wait[i]    = srvrun_wt_slot(c, i)->connect_stream_id + 1;
  srvrun_send_wt_close(cfg, c, i);
}

/* A live, not-yet-closing connection carrying WebTransport sessions (raw
 * QUIC closes its session with CONNECTION_CLOSE itself, srvrun_raw_close). */
static int srvrun_wt_shut_applies(const srvrun_conn* c) {
  return c->up && !c->closing && !srvrun_conn_is_raw(c);
}

static void srvrun_wt_shut_conn(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!srvrun_wt_shut_applies(c)) {
    return;
  }
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_wt_shut_one(cfg, c, i);
  }
}

/* Shutdown's last step before CONNECTION_CLOSE: end every live WT session
 * with its own WT_CLOSE_SESSION first, so the close metadata is not lost
 * behind the connection's close (draft-ietf-webtrans-http3-16 6). */
void srvrun_wt_close_all_live(const srvrun_cfg* cfg, srvrun_state* st) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    srvrun_wt_shut_conn(cfg, &st->conns[i]);
  }
}

/* Slot i no longer waits once the peer closed CONNECT stream id. */
static void srvrun_wt_close_wait_drop(srvrun_conn* c, int i, u64 id) {
  if (c->wt_close_wait[i] == id + 1) {
    c->wt_close_wait[i] = 0;
  }
}

/* The peer closed (FIN or RESET_STREAM) the stream this step reported
 * (closed_stream_id): stop waiting on it. */
void srvrun_wt_close_wait_note(srvrun_conn* c) {
  if (!c->l.closed_stream_seen) {
    return;
  }
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_wt_close_wait_drop(c, i, c->l.closed_stream_id);
  }
}

static int srvrun_wt_waits_any(const srvrun_conn* c) {
  int any = 0;
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    any |= c->wt_close_wait[i] != 0;
  }
  return any;
}

/* c still waits for the peer to close a CONNECT stream it was sent
 * WT_CLOSE_SESSION on; a connection gone or closing waits for nothing. */
static int srvrun_conn_wt_waits(const srvrun_conn* c) {
  return c->up && !c->closing && srvrun_wt_waits_any(c);
}

/* 1 while any connection still waits (srvrun_conn_wt_waits). */
int srvrun_wt_close_waiting(const srvrun_state* st) {
  int any = 0;
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    any |= srvrun_conn_wt_waits(&st->conns[i]);
  }
  return any;
}
