#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_drain_wt_close_one(
    const srvrun_cfg* cfg, srvrun_conn* c, int i);

/* draft-ietf-webtrans-http3-16 SS5.1/SS5.6/SS9.5: apply the peer's session
 * flow-control capsules (WT_MAX_DATA / WT_MAX_STREAMS / WT_STREAMS_BLOCKED)
 * arriving on session slot sidx's CONNECT stream; a malformed capsule or a
 * flow-control violation closes the session with the appropriate code. */
void srvrun_wt_rx_capsules_one(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx) {
  wired_srvloop_stream_slot* slot = srvrun_wt_rx_slot(c, sidx);
  srvrun_wt_caprx            x    = {0, 0, 0, WTERR_SESSION_GONE};
  if (!slot) {
    return;
  }
  if (srvrun_wt_rx_walk(cfg, c, sidx, slot, &x)) {
    srvrun_grant_body_credit(cfg, c, slot);
  } else {
    srvrun_wt_rx_fail(cfg, c, sidx, x.violation_code);
  }
}

/* Per-step receive pass over every session slot, same fan-out shape as
 * srvrun_drain_wt_close_pending. */
void srvrun_wt_rx_capsules(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_wt_rx_capsules_one(cfg, c, i);
  }
}

void srvrun_close_wt_on_stream_close(const srvrun_cfg* cfg, srvrun_conn* c) {
  int sidx = srvrun_wt_connect_stream_slot(c);
  srvrun_wt_close_wait_note(c);
  if (sidx >= 0) {
    srvrun_log_close(
        "wt session closed by peer (CONNECT stream)", wired_span_of(0, 0));
    srvrun_wt_connect_fin(c, sidx); /* draft-ietf-webtrans-http3-16 SS6 */
    srvrun_close_wt_session_slot(cfg, c, sidx, WTERR_SESSION_GONE);
  }
  c->l.closed_stream_seen = 0;
}

/* draft-ietf-webtrans-http3-15 SS4.2/SS4.4/8.2 (WTH3-067): drain a
 * wired_server_wt_close_session call latched at slot sidx (wt_close_pending's
 * own doc) -- send the WT_CLOSE_SESSION capsule with FIN on the CONNECT
 * stream, then reset every OTHER WT stream this session owns with WT_SESSION_
 * GONE (srvrun_close_wt_session_slot, which never touches the CONNECT stream
 * itself) and close the session. A capsule-encode failure (message too long
 * -- cannot happen, wired_server_wt_close_session already truncated it to
 * WTCAPSULE_CLOSE_MESSAGE_MAX -- or out overflow) still closes the
 * session: a peer that never received the capsule finds out via the CONNECT
 * stream's own FIN/reset either way, and leaving the session open forever on
 * a local encode failure would be worse; the CONNECT stream is then reset
 * with WT_SESSION_GONE instead (draft-ietf-webtrans-http3-16 6: closing it
 * abruptly also ends the session). */
void srvrun_send_wt_close(const srvrun_cfg* cfg, srvrun_conn* c, int sidx) {
  /* +4: WT_CLOSE_SESSION's fixed 32-bit Application Error Code field
   * (wtcapsule.h). +16: worst-case Capsule Type + Capsule Length varint
   * overhead (RFC 9000 SS16: a varint is at most 8 bytes each,
   * capsule_encode's own envelope) ahead of the 4-byte code and message
   * wired_wtcapsule_encode_close writes into this same buffer. */
  u8         body[16 + 4 + WTCAPSULE_CLOSE_MESSAGE_MAX];
  wired_obuf bob = obuf_of(body, sizeof body);
  if (!wired_wtcapsule_encode_close(
          &bob, c->wt_close_code[sidx],
          wired_span_of(c->wt_close_msg[sidx], c->wt_close_msg_len[sidx])) ||
      !srvrun_send_wt_capsule(c, sidx, wired_span_of(body, bob.len), 1)) {
    srvrun_reset_connect_stream_code(cfg, c, sidx, WTERR_SESSION_GONE);
  }
  srvrun_close_wt_session_slot(cfg, c, sidx, WTERR_SESSION_GONE);
}

/* draft-ietf-moq-transport-19 3.5 / -22 6.6: a raw-QUIC session is closed
 * by closing the connection -- an application CONNECTION_CLOSE (0x1d) whose
 * Error Code is the MoQT code itself, the message (cut at a UTF-8 boundary)
 * as Reason Phrase. srvrun_send_app_close enters the closing state and
 * fires wt_on_session_close once in this same step (TLA+ CloseLive). */
void srvrun_raw_close(const srvrun_cfg* cfg, srvrun_conn* c, int sidx) {
  wired_span m =
      wired_span_of(c->wt_close_msg[sidx], c->wt_close_msg_len[sidx]);
  usz n = wtcapsule_utf8_truncate_len(m, SRVRUN_RAW_CLOSE_REASON_MAX);
  srvrun_send_app_close(cfg, c, c->wt_close_code[sidx], wired_span_of(m.p, n));
}

/* Indexed by srvrun_conn_is_raw: WT_CLOSE_SESSION capsule, CONNECTION_CLOSE
 * (TLA+ RawCloseShape). */
static const srvrun_sess_close_fn srvrun_sess_close_by_raw[2] = {
    srvrun_send_wt_close, srvrun_raw_close};

static void srvrun_drain_wt_close_one(
    const srvrun_cfg* cfg, srvrun_conn* c, int i) {
  if (!c->wt_close_pending[i]) {
    return;
  }
  c->wt_close_pending[i] = 0;
  if (srvrun_wt_is_active(c, i)) {
    srvrun_sess_close_by_raw[srvrun_conn_is_raw(c)](cfg, c, i);
  }
}

/* Drain every session slot's pending wired_server_wt_close_session
 * (wt_close_pending, latched from an app callback), same per-step shape as
 * srvrun_wt_rx_capsules. */
void srvrun_drain_wt_close_pending(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_drain_wt_close_one(cfg, c, i);
  }
}

/* Seal latch entry i into out as its own 1-RTT packet: the stream reset
 * (srvrun_wt_reset_frames: RESET_STREAM_AT over the WT header when
 * negotiated, else RESET_STREAM, RFC 9000 19.4) with the app code mapped into
 * HTTP/3's WebTransport range (draft-ietf-webtrans-http3-15 SS4.4/8.2) plus the
 * final size captured at latch time -- NOT looked up now
 * (srvrun_wt_abort_reset's live lookup would read 0, the send slot was
 * already freed at latch time) -- or, for a wired_server_wt_stream_stop
 * entry, one STOP_SENDING (RFC 9000 19.5) for the peer-initiated stream
 * (see the wt_stream_reset_* latch fields' own doc). */
int srvrun_seal_wt_stream_reset(srvrun_conn* c, usz i, wired_obuf* out) {
  u8  pl[SRVRUN_RST_PL];
  usz n;
  u64 code = rawq_reset_code_out(
      srvrun_conn_is_raw(c), c->wt_stream_reset_app_code[i]);
  srvrun_wt_reset_in in = {
      c->wt_stream_reset_id[i], code, c->wt_stream_reset_final[i],
      c->wtx.reset_sid[i]};
  stop_sending_frame ss = {c->wt_stream_reset_id[i], code};
  n                     = c->wt_stream_reset_stop[i]
                              ? stop_sending_encode(pl, sizeof pl, &ss)
                              : srvrun_wt_reset_frames(c, &in, pl, sizeof pl);
  /* RFC 9000 13.3: kept and resent verbatim until ACKed */
  return srvrun_seal_kept(c, pl, n, out);
}
