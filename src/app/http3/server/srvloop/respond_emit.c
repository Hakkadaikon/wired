#include "app/http3/server/srvloop/respond_impl.h"

static int seal_confirm_onertt(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out);
static int emit_confirm(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out);
static int emit_response(const wired_srvloop_conn* c, wired_obuf* out);
static int produce_confirmed(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out);
static int emit_confirm_then_maybe_200(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out);
static int confirm_pending(const wired_srvloop* l);

/* Seal the confirmation 1-RTT packet (SETTINGS + HANDSHAKE_DONE, and the 200 +
 * received-packet ACK when a GET was decoded) into out, in one 1-RTT packet. */
static int seal_confirm_onertt(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out) {
  u8         pl[WIRED_SRVLOOP_BODY_MAX + 288];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  usz        pll;
  if (!srvloop_confirm_then_maybe_200(c, got_request, &plb)) {
    return 0;
  }
  pll = plb.len;
  pll += srvloop_app_ack_append(c->l, pl + pll, sizeof pl - pll);
  wired_srvloop_send_in sin = {
      wired_span_of(c->l->cli_scid, c->l->cli_scid_len),
      c->l->tx_pn++,
      -1,
      wired_span_of(pl, pll),
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(c->l, c->s, &sin, out);
}

/* RFC 9000 12.2: at confirmation, coalesce a long-header Handshake ACK and the
 * single 1-RTT packet (SETTINGS + HANDSHAKE_DONE, plus the 200 when a GET came
 * in the same datagram) into one datagram. */
static int emit_confirm(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out) {
  wired_obuf ob = obuf_of(out->p, out->cap);
  usz        hl;
  if (!srvloop_emit_handshake_ack(c, &ob)) {
    return 0;
  }
  hl = ob.len;
  ob = obuf_of(out->p + hl, out->cap - hl);
  if (!seal_confirm_onertt(c, got_request, &ob)) {
    return 0;
  }
  out->len = hl + ob.len;
  return 1;
}

/* RFC 9114 4.1 / RFC 9000 13.2.1: build a 200 (no body) for the decoded
 * request, then append a 1-RTT ACK of the received GET, sealed in one 1-RTT
 * packet. The response STREAM frame carries an explicit length, so a peer's
 * response decoder stops at it and ignores the trailing ACK. SETTINGS were
 * already sent at confirmation (build_response needs settings_sent). */
static int emit_response(const wired_srvloop_conn* c, wired_obuf* out) {
  u8         pl[WIRED_SRVLOOP_BODY_MAX + 288];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  usz        rl;
  if (!srvloop_response_frame(c->l, 1, &plb)) {
    return 0;
  }
  rl = plb.len;
  rl += srvloop_app_ack_append(c->l, pl + rl, sizeof pl - rl);
  wired_srvloop_send_in sin = {
      wired_span_of(c->l->cli_scid, c->l->cli_scid_len),
      c->l->tx_pn++,
      -1,
      wired_span_of(pl, rl),
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(c->l, c->s, &sin, out);
}

/* RFC 9000 13.2.1: a 1-RTT packet carrying only an ACK of the received packet,
 * sent post-confirmation when no request decoded — so the confirmation is not
 * re-emitted yet the client's 1-RTT packet is still acknowledged. Only sent
 * when the delayed-ACK policy actually calls for one now (RFC 9000
 * 13.2.1/13.2.2) -- unlike the piggyback callers above, this packet exists
 * solely to carry the ACK, so the delay window matters here. */
int srvloop_emit_ack_only(const wired_srvloop_conn* c, wired_obuf* out) {
  u8  pl[288]; /* room for ACK_MAX_RANGES ranges, not just one pn */
  usz a = srvloop_app_ack_append_if_due(c->l, pl, sizeof pl);
  if (a == 0) {
    return 0;
  }
  wired_srvloop_send_in sin = {
      wired_span_of(c->l->cli_scid, c->l->cli_scid_len),
      c->l->tx_pn++,
      -1,
      wired_span_of(pl, a),
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(c->l, c->s, &sin, out);
}

/* Post-confirmation outbound: a decoded GET yields a 200 (+ACK), else a bare
 * ACK of the received 1-RTT packet, else nothing. The confirmation is never
 * re-emitted here (RFC 9000 13.2.1). */
static int produce_confirmed(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out) {
  if (got_request) {
    return emit_response(c, out);
  }
  return srvloop_emit_ack_only(c, out);
}

/* RFC 9000 12.2 / RFC 9114 6.2.1: emit the confirmation — a Handshake ACK plus
 * one 1-RTT packet that carries SETTINGS + HANDSHAKE_DONE and, when this
 * datagram also carried a GET, the 200 in the SAME 1-RTT payload (short-header
 * packets cannot coalesce). So curl receives SETTINGS to establish HTTP/3 and
 * the 200 together, never the 200 alone with SETTINGS still missing. */
static int emit_confirm_then_maybe_200(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out) {
  if (!emit_confirm(c, got_request, out)) {
    return 0;
  }
  c->l->hs_done_sent = 1;
  c->l->ticket_sent  = 1;
  return 1;
}

/* 1 while the one-time confirmation (SETTINGS + HANDSHAKE_DONE) has not been
 * emitted yet. It is sent exactly once — coalescing the 200 when the confirming
 * datagram also carried a GET — and not repeated thereafter (RFC 9000 13.2.1).
 */
static int confirm_pending(const wired_srvloop* l) { return !l->hs_done_sent; }

int wired_srvloop_produce(
    const wired_srvloop_conn* conn, int got_request, wired_obuf* out) {
  if (confirm_pending(conn->l)) {
    return emit_confirm_then_maybe_200(conn, got_request, out);
  }
  return produce_confirmed(conn, got_request, out);
}

int wired_srvloop_reconfirm(const wired_srvloop_conn* conn, wired_obuf* out) {
  wired_srvloop* l = conn->l;
  if (!l->hs_done_sent || l->confirm_frames_len == 0) {
    return 0;
  }
  wired_srvloop_send_in sin = {
      wired_span_of(l->cli_scid, l->cli_scid_len),
      l->tx_pn++,
      -1,
      wired_span_of(l->confirm_frames, l->confirm_frames_len),
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(conn->l, conn->s, &sin, out);
}
