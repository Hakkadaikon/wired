#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_aead_limit_reached(const srvrun_conn* c);
static void srvrun_close_on_aead_limit(const srvrun_cfg* cfg, srvrun_conn* c);
static int  srvrun_close_on_req_frame_error(
    const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_wt_signal_latched(
    const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_ctrl_overflow(const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_refused_overflow(
    const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_flow_violation(
    const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_aead_reached(const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_aead_or_cid(const srvrun_cfg* cfg, srvrun_conn* c);

/* 1 if this step's own gathering (dispatch.c) latched a connection-ending
 * violation and closed c over it -- datagram_violation (RFC 9221 3) or
 * wt_signal_mid_stream_violation (draft-ietf-webtrans-http3-15 4.3), checked
 * and cleared together so srvrun_on_step itself carries only one guard for
 * both (CCN). Datagram is checked first only because it was the original,
 * single violation; a step latching both simply chooses the datagram close
 * (RFC 9000 10.2: any CONNECTION_CLOSE ends the connection, so it does not
 * matter which of two same-step violations sends it). */
/* RFC 9001 6.6: the 1-RTT auth-failure count (srvloop's recv path) reached
 * the negotiated AEAD's integrity limit -- the connection MUST close with
 * AEAD_LIMIT_REACHED. */
static int srvrun_aead_limit_reached(const srvrun_conn* c) {
  return aead_integrity_exceeded(
      c->s.ku_auth_fail, aead_is_chacha(c->s.sdrv.cipher_suite));
}

static void srvrun_close_on_aead_limit(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "AEAD integrity limit reached";
  srvrun_send_transport_close(
      cfg, c, ERR_AEAD_LIMIT_REACHED, wired_span_of(reason, sizeof reason - 1));
}

/* RFC 9114 7.1: a request stream ended inside a frame -- "MUST be treated
 * as a connection error of type H3_FRAME_ERROR" (srvloop's body window
 * latched it). */
static int srvrun_close_on_req_frame_error(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "request stream ended inside a frame";
  if (!c->l.req_frame_error) return 0;
  c->l.req_frame_error = 0;
  srvrun_send_app_close(
      cfg, c, H3_FRAME_ERROR, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

/* The latched WT signal violation, consumed. */
static int srvrun_close_on_wt_signal_latched(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!c->l.wt_signal_mid_stream_violation) return 0;
  c->l.wt_signal_mid_stream_violation = 0;
  srvrun_close_on_wt_signal_violation(cfg, c);
  return 1;
}

/* RFC 9114 6.2.1: the peer's control-stream backlog outgrew its buffer
 * (wired_srvloop.ctrl_overflow) -- closing beats silently losing SETTINGS,
 * GOAWAY or PRIORITY_UPDATE frames past it. */
static int srvrun_close_on_ctrl_overflow(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "control stream backlog too large";
  if (!c->l.ctrl_overflow) return 0;
  c->l.ctrl_overflow = 0;
  srvrun_send_app_close(
      cfg, c, H3_EXCESSIVE_LOAD, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

/* The two H3_FRAME_ERROR latches (the WT signal, a truncated request), then
 * the control-stream overflow. */
int srvrun_close_on_frame_error(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (srvrun_close_on_wt_signal_latched(cfg, c)) return 1;
  if (srvrun_close_on_req_frame_error(cfg, c)) return 1;
  return srvrun_close_on_ctrl_overflow(cfg, c);
}

/* RFC 9000 4.6: a WT bidi refusal found the queue full -- the peer opened
 * past the MAX_STREAMS this server sent (wired_srvloop.wt_refused). */
static int srvrun_close_on_refused_overflow(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "stream limit exceeded";
  if (!c->l.wt_refused_overflow) return 0;
  c->l.wt_refused_overflow = 0;
  srvrun_send_transport_close(
      cfg, c, ERR_STREAM_LIMIT_ERROR, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

/* RFC 9000 4.1: the peer sent past a stream credit this server granted -- a
 * request stream past its window (srvloop's flow_control_violation), or a
 * WT stream past its slot's window (win.dropped_bytes): neither credit ever
 * exceeds its window (bodywin_credit_due, srvrun_wt_slot_credit_ceiling). */
int srvrun_flow_violated(const srvrun_conn* c) {
  return c->l.flow_control_violation || srvrun_wtwin_dropped(c) != 0;
}

static int srvrun_close_on_flow_violation(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "stream data past flow control credit";
  if (!srvrun_flow_violated(c)) return 0;
  c->l.flow_control_violation = 0;
  srvrun_send_transport_close(
      cfg, c, ERR_FLOW_CONTROL_ERROR, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

/* The AEAD integrity limit (RFC 9001 6.6). */
static int srvrun_close_on_aead_reached(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!srvrun_aead_limit_reached(c)) return 0;
  srvrun_close_on_aead_limit(cfg, c);
  return 1;
}

/* RFC 9000 19.15/5.1.1: a malformed NEW_CONNECTION_ID
 * (FRAME_ENCODING_ERROR), or one the pool rejected (srvrun_conn.cid_err). */
int srvrun_close_on_cid(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "connection id error";
  u8 code = c->l.ncid_malformed ? ERR_FRAME_ENCODING_ERROR : c->cid_err;
  if (!code) return 0;
  c->l.ncid_malformed = 0;
  c->cid_err          = 0;
  srvrun_send_transport_close(
      cfg, c, code, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

/* The AEAD integrity limit, then a connection ID error. */
static int srvrun_close_on_aead_or_cid(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (srvrun_close_on_aead_reached(cfg, c)) return 1;
  return srvrun_close_on_cid(cfg, c);
}

/* The stream-limit overflow, a flow-control violation, then the AEAD
 * integrity limit and connection ID errors. */
int srvrun_close_on_limits(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (srvrun_close_on_refused_overflow(cfg, c)) return 1;
  if (srvrun_close_on_flow_violation(cfg, c)) return 1;
  return srvrun_close_on_aead_or_cid(cfg, c);
}
