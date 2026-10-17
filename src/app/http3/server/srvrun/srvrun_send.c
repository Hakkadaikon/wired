#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_continue_payload(u64 stream_id, wired_obuf* plb, usz* h3_len);
static int srvrun_seal_continue(
    srvrun_conn* c, u64 stream_id, wired_obuf* out, usz* h3_len);
static usz srvrun_transport_close_payload(
    u64 error_code, wired_span reason, wired_obuf* plb);

/* Send an application-level CONNECTION_CLOSE as its own 1-RTT packet (e.g.
 * srvrun_close_on_bad_qsid's RFC 9297 2.1 H3_DATAGRAM_ERROR) and enter the
 * closing state (srvrun_close_send). */
void srvrun_send_app_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, wired_span reason) {
  u8         pl[SRVRUN_CLOSE_PL_MAX];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  usz        pln = srvrun_app_close_payload(error_code, reason, &plb);
  if (srvrun_close_send(cfg, c, wired_span_of(pl, pln)))
    srvrun_log_close("conn closed by server (app): ", reason);
}

/* RFC 9110 10.1.1: build a bare "100 Continue" HEADERS frame (no DATA, RFC
 * 9114 4.1) wrapped in a STREAM frame at absolute offset 0 of the request
 * stream -- an interim response, so unlike the final response it is not
 * ACK-tracked by wired_sendsess: losing it costs nothing (RFC 9110 10.1.1
 * lets a client proceed after its own timeout regardless), matching
 * srvrun_seal_close_pl's own fire-and-forget idiom for single-packet sends.
 * *h3_len receives the HEADERS frame's own byte length (the request stream's
 * new base offset the final response must continue from). Returns 1 with
 * plb->len set, 0 on overflow. */
static int srvrun_continue_payload(
    u64 stream_id, wired_obuf* plb, usz* h3_len) {
  u8           h3[16];
  wired_obuf   h3b = obuf_of(h3, sizeof h3);
  stream_frame f;
  if (!h3resp_prefix(100, 0, 0, &h3b)) return 0;
  f       = (stream_frame){stream_id, 0, h3b.len, h3, 0};
  *h3_len = h3b.len;
  return appdata_stream_frame(&f, plb) != 0;
}

/* Seal the 100-continue payload above into out as its own 1-RTT packet.
 * *h3_len receives the HEADERS frame's byte length (see
 * srvrun_continue_payload). Returns 1 with out->len set, 0 if nothing was
 * built/sealed. */
static int srvrun_seal_continue(
    srvrun_conn* c, u64 stream_id, wired_obuf* out, usz* h3_len) {
  u8                    pl[64];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!srvrun_continue_payload(stream_id, &plb, h3_len)) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, plb.len),
      0,
      0,
      0,
      0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Send RFC 9110 10.1.1's "100 Continue" interim response for stream_id, an
 * informational HEADERS frame issued before the final response -- srvrun's
 * one caller (srvrun_start_app_resp) uses the returned byte length as the
 * final response's wired_sendsess_set_base_offset so it continues the same
 * QUIC stream right after this frame rather than overlapping it. Returns 0
 * (no base offset shift) if sealing failed or cfg has no socket to send on. */
usz srvrun_send_continue(const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  u8         out[128];
  wired_obuf ob     = obuf_of(out, sizeof out);
  usz        h3_len = 0;
  if (!srvrun_seal_continue(c, stream_id, &ob, &h3_len)) return 0;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "100 Continue sent\n");
  return h3_len;
}

/* RFC 9000 10.2.3: a transport-level CONNECTION_CLOSE (type 0x1c, is_app=0)
 * carrying a standard RFC 9000 20.1 error code -- the sibling of
 * srvrun_app_close_payload for a violation the transport itself detects (e.g.
 * RFC 9221 3's PROTOCOL_VIOLATION), rather than an HTTP/3/WebTransport
 * application error. frame_type 0 (unknown/unspecified) matches
 * wired_srvboot_refusal's own transport-close payload. */
static usz srvrun_transport_close_payload(
    u64 error_code, wired_span reason, wired_obuf* plb) {
  conn_close_frame cc = {0, error_code, 0, reason.n, reason.p};
  return frame_put_conn_close(plb->p, plb->cap, &cc);
}

/* Send a transport-level CONNECTION_CLOSE as its own 1-RTT packet (RFC 9000
 * 20.1 error code, e.g. ERR_PROTOCOL_VIOLATION) and enter the closing state
 * (srvrun_close_send). */
void srvrun_send_transport_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, wired_span reason) {
  u8         pl[SRVRUN_CLOSE_PL_MAX];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  usz        pln = srvrun_transport_close_payload(error_code, reason, &plb);
  if (srvrun_close_send(cfg, c, wired_span_of(pl, pln)))
    srvrun_log_close("conn closed by server (transport): ", reason);
}
