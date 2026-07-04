#include "app/http3/server/srvloop/respond.h"

#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/send.h"
#include "tls/handshake/core/tls/newsessionticket.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_build.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/stream/data/appdata/stream_send.h"

#define WIRED_SRVLOOP_RESP_STREAM 0
#define WIRED_SRVLOOP_CTRL_STREAM              \
  3 /* RFC 9114 6.2.1: first server uni stream \
     */

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame for the single packet number pn.
 */
static usz encode_ack_one(u8 *frames, usz cap, u64 pn) {
  quic_ack_frame f = {0};
  f.n_ranges       = 1;
  f.ranges[0].hi   = pn;
  f.ranges[0].lo   = pn;
  return quic_ack_encode(frames, cap, &f);
}

/* RFC 9000 13.2.1: seal a Handshake packet that carries only an ACK of the
 * client Finished's actual packet number (no CRYPTO), so curl stops
 * retransmitting it. The PN is recorded by note_hs_rx as packets arrive; curl
 * leads with an ACK-only Handshake packet, so the Finished is not at PN 0 and a
 * fixed ACK of 0 left it unacknowledged — the client then PTO-retransmitted it
 * for ~4s before the handshake completed (the appconnect stall). */
static int emit_handshake_ack(const wired_srvloop_conn *c, quic_obuf *out) {
  wired_srvloop_dirkeys dk;
  u8                    frames[16];
  usz                   fl;
  if (!wired_srvloop_seal_keys(c->s, QUIC_LEVEL_HANDSHAKE, &dk)) return 0;
  fl = encode_ack_one(frames, sizeof frames, c->l->hs_rx_pn);
  if (fl == 0) return 0;
  quic_protect_keys pk = {dk.keys, &dk.hp};
  quic_hspkt_desc   d  = {
      quic_span_of(c->l->cli_scid, c->l->cli_scid_len),
      quic_span_of(c->s->sdrv.iscid, c->s->sdrv.iscid_len), c->l->hs_tx_pn++,
      quic_span_of(frames, fl)};
  return quic_hspkt_build(&pk, &d, out); /* out->len 0 unless built */
}

/* RFC 9114 6.2.1: wrap the control-stream type + SETTINGS in a STREAM frame on
 * the first server unidirectional stream (id 3, no FIN: the stream stays open).
 */
static int build_settings_frame(wired_srvloop *l, quic_obuf *out) {
  u8                ctl[64];
  quic_obuf         ctlb = quic_obuf_of(ctl, sizeof ctl);
  quic_stream_frame f;
  if (!wired_h3srv_open_control(&l->h3, &ctlb)) return 0;
  f = (quic_stream_frame){WIRED_SRVLOOP_CTRL_STREAM, 0, ctlb.len, ctl, 0};
  return quic_appdata_stream_frame(&f, out);
}

/* RFC 8446 4.6.1 / RFC 9001 4: server session tickets are sealed under a
 * fixed key for the process lifetime.
 * ponytail: one fixed key for the process lifetime, no rotation; a real
 * deployment needs periodic key rotation (and multi-key acceptance during
 * overlap) so a leaked key does not compromise every ticket ever issued. */
static const u8 g_ticket_key[QUIC_TICKET_KEY_LEN] = {
    0x77, 0x69, 0x72, 0x65, 0x64, 0x2d, 0x74, 0x6b, 0x74, 0x2d, 0x6b,
    0x65, 0x79, 0x2d, 0x30, 0x30, 0x77, 0x69, 0x72, 0x65, 0x64, 0x2d,
    0x74, 0x6b, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x30, 0x31};

/* RFC 8446 4.6.1: seal a fresh session ticket (fixed 2h lifetime; this SDK has
 * no clock, so issued_at is left 0 and resumption checks lifetime, not age)
 * and append it as a CRYPTO frame (RFC 9000 19.6) to a 1-RTT payload. */
static int append_ticket_frame(quic_obuf *out) {
  u8                msg[64 + QUIC_TICKET_SEALED_LEN];
  quic_ticket       t = {{0}, 0, 7200};
  quic_crypto_frame cf;
  usz               mlen =
      quic_tls_new_session_ticket_encode(msg, sizeof msg, &t, g_ticket_key);
  usz written;
  if (mlen == 0) return 0;
  cf      = (quic_crypto_frame){0, mlen, msg};
  written = quic_frame_put_crypto(out->p + out->len, out->cap - out->len, &cf);
  if (written == 0) return 0;
  out->len += written;
  return 1;
}

/* SETTINGS (RFC 9114 6.2.1) followed by a session ticket (RFC 8446 4.6.1),
 * the head of the confirmation payload. */
static int confirm_head(wired_srvloop *l, quic_obuf *out) {
  if (!build_settings_frame(l, out)) return 0;
  return append_ticket_frame(out);
}

/* The 1-RTT payload sent at confirmation: confirm_head, then HANDSHAKE_DONE
 * (RFC 9000 19.20) last — callers rely on HANDSHAKE_DONE being the trailing
 * frame. */
static int confirm_payload(const wired_srvloop_conn *c, quic_obuf *out) {
  quic_obuf ob = quic_obuf_of(out->p, out->cap);
  usz       a;
  if (!confirm_head(c->l, &ob)) return 0;
  a  = ob.len;
  ob = quic_obuf_of(out->p + a, out->cap - a);
  if (!wired_server_handshake_done(c->s, &ob)) return 0;
  out->len = a + ob.len;
  return 1;
}

/* RFC 9000 13.2.1: append an ACK of the last received 1-RTT packet number to a
 * 1-RTT payload, so the client stops retransmitting it. Returns the ACK length
 * (0 if no 1-RTT packet has been received yet). */
static usz app_ack_append(wired_srvloop *l, u8 *buf, usz cap) {
  if (!l->app_rx_seen) return 0;
  return encode_ack_one(buf, cap, l->app_rx_pn);
}

#define WIRED_SRVLOOP_BODY_MAX                                                \
  1024 /* ponytail: app response body cap; raise here if a handler needs more \
        */

/* RFC 9110 9.3: ask the registered handler to build the response body for the
 * decoded request. No handler (or it declines) -> a body-less 200. The body is
 * written into the caller's buffer; *body_len is 0 when there is none.
 * *content_type is left at its caller-supplied value (0) unless the handler
 * sets it. */
static const u8 *build_body(
    wired_srvloop *l, u8 *body, usz *body_len, const char **content_type) {
  quic_obuf ob = quic_obuf_of(body, WIRED_SRVLOOP_BODY_MAX);
  *body_len    = 0;
  if (l->on_request && l->on_request(l->req_ctx, &l->req, &ob, content_type)) {
    *body_len = ob.len;
    return body;
  }
  return (const u8 *)0;
}

/* RFC 9114 4.1 / 4.3.2: the 200 STREAM frame for the decoded request, carrying
 * the handler-built body; an empty section when no request was decoded. */
static int response_frame(wired_srvloop *l, int got_request, quic_obuf *out) {
  u8          body[WIRED_SRVLOOP_BODY_MAX];
  usz         body_len;
  const u8   *b;
  const char *content_type = 0;
  if (!got_request) {
    out->len = 0;
    return 1;
  }
  b = build_body(l, body, &body_len, &content_type);
  {
    wired_h3srv_send_in send = {
        WIRED_SRVLOOP_RESP_STREAM,
        {200, quic_span_of(b, body_len), content_type}};
    return wired_h3srv_build_response(&l->h3, &send, out);
  }
}

/* RFC 9000 12.2 / 19.4: a short-header (1-RTT) packet carries no length and
 * must be the datagram's last packet, so the confirmation and a coalesced 200
 * cannot be two separate 1-RTT packets — they share ONE payload. SETTINGS +
 * HANDSHAKE_DONE come first (build_settings_frame must mark SETTINGS sent
 * before the 200 may be built), then the 200 STREAM when a GET was decoded;
 * otherwise the payload is the confirmation alone. Frame order within a packet
 * does not constrain HTTP/3 stream order, so a peer routes each STREAM by its
 * id. */
static int confirm_then_maybe_200(
    const wired_srvloop_conn *c, int got_request, quic_obuf *out) {
  quic_obuf ob = quic_obuf_of(out->p, out->cap);
  usz       a;
  if (!confirm_payload(c, &ob)) return 0;
  a  = ob.len;
  ob = quic_obuf_of(out->p + a, out->cap - a);
  if (!response_frame(c->l, got_request, &ob)) return 0;
  out->len = a + ob.len;
  return 1;
}

/* Seal the confirmation 1-RTT packet (SETTINGS + HANDSHAKE_DONE, and the 200 +
 * received-packet ACK when a GET was decoded) into out, in one 1-RTT packet. */
static int seal_confirm_onertt(
    const wired_srvloop_conn *c, int got_request, quic_obuf *out) {
  u8        pl[WIRED_SRVLOOP_BODY_MAX + 288];
  quic_obuf plb = quic_obuf_of(pl, sizeof pl);
  usz       pll;
  if (!confirm_then_maybe_200(c, got_request, &plb)) return 0;
  pll = plb.len;
  pll += app_ack_append(c->l, pl + pll, sizeof pl - pll);
  wired_srvloop_send_in sin = {
      quic_span_of(c->l->cli_scid, c->l->cli_scid_len), c->l->tx_pn++, -1,
      quic_span_of(pl, pll), 0};
  return wired_srvloop_send_onertt(c->s, &sin, out);
}

/* RFC 9000 12.2: at confirmation, coalesce a long-header Handshake ACK and the
 * single 1-RTT packet (SETTINGS + HANDSHAKE_DONE, plus the 200 when a GET came
 * in the same datagram) into one datagram. */
static int emit_confirm(
    const wired_srvloop_conn *c, int got_request, quic_obuf *out) {
  quic_obuf ob = quic_obuf_of(out->p, out->cap);
  usz       hl;
  if (!emit_handshake_ack(c, &ob)) return 0;
  hl = ob.len;
  ob = quic_obuf_of(out->p + hl, out->cap - hl);
  if (!seal_confirm_onertt(c, got_request, &ob)) return 0;
  out->len = hl + ob.len;
  return 1;
}

/* RFC 9114 4.1 / RFC 9000 13.2.1: build a 200 (no body) for the decoded
 * request, then append a 1-RTT ACK of the received GET, sealed in one 1-RTT
 * packet. The response STREAM frame carries an explicit length, so a peer's
 * response decoder stops at it and ignores the trailing ACK. SETTINGS were
 * already sent at confirmation (build_response needs settings_sent). */
static int emit_response(const wired_srvloop_conn *c, quic_obuf *out) {
  u8        pl[WIRED_SRVLOOP_BODY_MAX + 288];
  quic_obuf plb = quic_obuf_of(pl, sizeof pl);
  usz       rl;
  if (!response_frame(c->l, 1, &plb)) return 0;
  rl = plb.len;
  rl += app_ack_append(c->l, pl + rl, sizeof pl - rl);
  wired_srvloop_send_in sin = {
      quic_span_of(c->l->cli_scid, c->l->cli_scid_len), c->l->tx_pn++, -1,
      quic_span_of(pl, rl), 0};
  return wired_srvloop_send_onertt(c->s, &sin, out);
}

/* RFC 9000 13.2.1: a 1-RTT packet carrying only an ACK of the received packet,
 * sent post-confirmation when no request decoded — so the confirmation is not
 * re-emitted yet the client's 1-RTT packet is still acknowledged. */
static int emit_ack_only(const wired_srvloop_conn *c, quic_obuf *out) {
  u8  pl[16];
  usz a = app_ack_append(c->l, pl, sizeof pl);
  if (a == 0) return 0;
  wired_srvloop_send_in sin = {
      quic_span_of(c->l->cli_scid, c->l->cli_scid_len), c->l->tx_pn++, -1,
      quic_span_of(pl, a), 0};
  return wired_srvloop_send_onertt(c->s, &sin, out);
}

/* Post-confirmation outbound: a decoded GET yields a 200 (+ACK), else a bare
 * ACK of the received 1-RTT packet, else nothing. The confirmation is never
 * re-emitted here (RFC 9000 13.2.1). */
static int produce_confirmed(
    const wired_srvloop_conn *c, int got_request, quic_obuf *out) {
  if (got_request) return emit_response(c, out);
  return emit_ack_only(c, out);
}

/* RFC 9000 12.2 / RFC 9114 6.2.1: emit the confirmation — a Handshake ACK plus
 * one 1-RTT packet that carries SETTINGS + HANDSHAKE_DONE and, when this
 * datagram also carried a GET, the 200 in the SAME 1-RTT payload (short-header
 * packets cannot coalesce). So curl receives SETTINGS to establish HTTP/3 and
 * the 200 together, never the 200 alone with SETTINGS still missing. */
static int emit_confirm_then_maybe_200(
    const wired_srvloop_conn *c, int got_request, quic_obuf *out) {
  if (!emit_confirm(c, got_request, out)) return 0;
  c->l->hs_done_sent = 1;
  c->l->ticket_sent  = 1;
  return 1;
}

/* 1 while the one-time confirmation (SETTINGS + HANDSHAKE_DONE) has not been
 * emitted yet. It is sent exactly once — coalescing the 200 when the confirming
 * datagram also carried a GET — and not repeated thereafter (RFC 9000 13.2.1).
 */
static int confirm_pending(const wired_srvloop *l) { return !l->hs_done_sent; }

int wired_srvloop_produce(
    const wired_srvloop_conn *conn, int got_request, quic_obuf *out) {
  if (confirm_pending(conn->l))
    return emit_confirm_then_maybe_200(conn, got_request, out);
  return produce_confirmed(conn, got_request, out);
}
