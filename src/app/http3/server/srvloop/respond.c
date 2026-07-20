#include "app/http3/server/srvloop/respond.h"

#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/send.h"
#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/newsessionticket.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_build.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/recovery/detect/ackgen/ackrange.h"
#include "transport/recovery/detect/ackgen/ackrangeconv.h"
#include "transport/recovery/detect/recovery/ackdelay.h"
#include "transport/stream/data/appdata/stream_send.h"

#define WIRED_SRVLOOP_RESP_STREAM 0
#define WIRED_SRVLOOP_CTRL_STREAM              \
  3 /* RFC 9114 6.2.1: first server uni stream \
     */

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame for the single packet number pn.
 */
static usz encode_ack_one(u8* frames, usz cap, u64 pn) {
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
static int emit_handshake_ack(const wired_srvloop_conn* c, quic_obuf* out) {
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
  /* out->len 0 unless built */
  return quic_hspkt_build_suite(c->s->sdrv.cipher_suite, &pk, &d, out);
}

/* RFC 9114 6.2.1: wrap the control-stream type + SETTINGS in a STREAM frame on
 * the first server unidirectional stream (id 3, no FIN: the stream stays open).
 */
static int build_settings_frame(wired_srvloop* l, quic_obuf* out) {
  u8                ctl[64];
  quic_obuf         ctlb = quic_obuf_of(ctl, sizeof ctl);
  quic_stream_frame f;
  /* advertise WebTransport + H3 datagrams only when the QUIC transport also
   * negotiated max_datagram_frame_size (RFC 9297 2.1.1 MUST) */
  if (!wired_h3srv_open_control(
          &l->h3, l->we_advertised_max_datagram > 0, &ctlb))
    return 0;
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

const u8* wired_srvloop_ticket_key(void) { return g_ticket_key; }

/* RFC 8446 4.6.1: seal a fresh session ticket (fixed 2h lifetime; this SDK has
 * no clock, so issued_at is left 0 and resumption checks lifetime, not age)
 * and append it as a CRYPTO frame (RFC 9000 19.6) to a 1-RTT payload. */
static int append_ticket_frame(quic_obuf* out) {
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
static int confirm_head(wired_srvloop* l, quic_obuf* out) {
  if (!build_settings_frame(l, out)) return 0;
  return append_ticket_frame(out);
}

/* Capture the confirmation frames for a later replay
 * (wired_srvloop_reconfirm); an oversized payload simply leaves the cache
 * empty (no replay available) rather than truncating. */
static void confirm_cache_store(wired_srvloop* l, const u8* p, usz n) {
  if (n > sizeof l->confirm_frames) return;
  quic_memcpy(l->confirm_frames, p, n);
  l->confirm_frames_len = (u16)n;
}

/* The 1-RTT payload sent at confirmation: confirm_head, then HANDSHAKE_DONE
 * (RFC 9000 19.20) last — callers rely on HANDSHAKE_DONE being the trailing
 * frame. */
static int confirm_payload(const wired_srvloop_conn* c, quic_obuf* out) {
  quic_obuf ob = quic_obuf_of(out->p, out->cap);
  usz       a;
  if (!confirm_head(c->l, &ob)) return 0;
  a  = ob.len;
  ob = quic_obuf_of(out->p + a, out->cap - a);
  if (!wired_server_handshake_done(c->s, &ob)) return 0;
  out->len = a + ob.len;
  confirm_cache_store(c->l, out->p, out->len);
  return 1;
}

/* RFC 9000 13.2.1/13.2.2/19.3: whether an ACK is owed on the App pn space
 * right now (quic_ackpolicy, already latched by srvloop.c's receive path). */
static int app_ack_due(const wired_srvloop* l) {
  return quic_ackpolicy_should_ack(
      &l->app_ack_policy, l->now_ms, WIRED_SRVLOOP_MAX_ACK_DELAY_MS);
}

/* 1 if l has ever counted an ECT(0)/ECT(1)/CE datagram. Split out of
 * app_ack_set_ecn so its && chain doesn't push that function's CCN past the
 * gate (ccn-and-complexity.md: each && is its own branch). */
static int app_ack_ecn_any_seen(const wired_srvloop* l) {
  return l->ecn_ect0 != 0 || l->ecn_ect1 != 0 || l->ecn_ce != 0;
}

/* RFC 9000 19.3.2: attach l's cumulative ECN counts to f (type 0x03) when at
 * least one of ECT(0)/ECT(1)/CE has ever been seen on this connection; leaves
 * f as a plain type-0x02 ACK (has_ecn stays 0) when all three are still zero
 * -- the pre-existing non-ECN wire format for a connection/path that never
 * reported an ECN-marked datagram. */
static void app_ack_set_ecn(const wired_srvloop* l, quic_ack_frame* f) {
  if (!app_ack_ecn_any_seen(l)) return;
  f->has_ecn = 1;
  f->ect0    = l->ecn_ect0;
  f->ect1    = l->ecn_ect1;
  f->ce      = l->ecn_ce;
}

/* RFC 9000 19.3: encode a full multi-range ACK frame from the App pn
 * space's received-pn window (quic_pnspaces_recv, RFC 9000 12.3/13.2.1),
 * with an ack_delay reflecting how long the oldest unacked eliciting packet
 * has waited (quic_ack_delay_encode, RFC 9000 19.3/13.2.5), and this
 * connection's cumulative ECN counts (RFC 9000 19.3.2, app_ack_set_ecn).
 * Returns the encoded length, 0 if the window is empty or encoding fails
 * (e.g. the range count would overflow QUIC_ACK_MAX_RANGES -- caller then
 * sends no ACK this round rather than a corrupt one). */
static usz app_ack_encode_ranges(wired_srvloop* l, u8* buf, usz cap) {
  u64            raw[2 * QUIC_ACK_MAX_RANGES + 1];
  u64            largest;
  quic_u64obuf   ranges = {raw, sizeof raw / sizeof raw[0], 0};
  quic_ack_frame f      = {0};
  if (!quic_pnspaces_ack_ranges(
          &l->ack_recv, QUIC_PNS_APP,
          &(quic_pnspaces_ack_out){&largest, &ranges}))
    return 0;
  if (!quic_ackrangeconv_to_frame(largest, raw, ranges.len, &f)) return 0;
  f.ack_delay = quic_ack_delay_encode(
      (l->now_ms - l->app_ack_policy.since_tick) * 1000,
      QUIC_ACK_DELAY_EXPONENT_DEFAULT);
  app_ack_set_ecn(l, &f);
  return quic_ack_encode(buf, cap, &f);
}

/* RFC 9000 13.2.1: append a multi-range ACK of the App pn space's received
 * packets to a 1-RTT payload that already carries other data (confirmation
 * or a 200 response) -- piggybacking costs nothing extra on the wire, so
 * these paths always attach a pending ACK rather than waiting out the delay
 * window on a packet that's going out anyway. Nothing to append (the App
 * space's window is empty) is the only reason this returns 0. Clears the
 * pending state once encoded (quic_ackpolicy_on_ack_sent) so the next
 * step's due-check starts fresh. */
static usz app_ack_append(wired_srvloop* l, u8* buf, usz cap) {
  usz n = app_ack_encode_ranges(l, buf, cap);
  if (n) quic_ackpolicy_on_ack_sent(&l->app_ack_policy);
  return n;
}

/* RFC 9000 13.2.1/13.2.2: append an ACK ONLY when one is actually due
 * (quic_ackpolicy_should_ack) -- for emit_ack_only's bare-ACK packet, where
 * sending one costs a whole extra packet on the wire, so the delay window
 * genuinely matters (unlike app_ack_append's piggyback callers above). */
static usz app_ack_append_if_due(wired_srvloop* l, u8* buf, usz cap) {
  if (!app_ack_due(l)) return 0;
  return app_ack_append(l, buf, cap);
}

#define WIRED_SRVLOOP_BODY_MAX                                                \
  1024 /* ponytail: app response body cap; raise here if a handler needs more \
        */

/* RFC 9110 9.3: ask the registered handler to build the response body for the
 * decoded request. No handler (or it declines) -> a body-less 200. The body is
 * written into the caller's buffer; *body_len is 0 when there is none.
 * *content_type is left at its caller-supplied value (0) unless the handler
 * sets it. */
static const u8* build_body(
    wired_srvloop* l, u8* body, usz* body_len, const char** content_type) {
  quic_obuf ob         = quic_obuf_of(body, WIRED_SRVLOOP_BODY_MAX);
  int       more       = 0;
  u64       total_size = 0;
  *body_len            = 0;
  if (l->on_request &&
      l->on_request(
          l->req_ctx, &l->req, 0, &ob, content_type, &more, &total_size)) {
    *body_len = ob.len;
    return body;
  }
  return (const u8*)0;
}

/* RFC 9114 4.1 / 4.3.2: the 200 STREAM frame for the decoded request, carrying
 * the handler-built body; an empty section when no request was decoded. */
static int response_frame(wired_srvloop* l, int got_request, quic_obuf* out) {
  u8          body[WIRED_SRVLOOP_BODY_MAX];
  usz         body_len;
  const u8*   b;
  const char* content_type = 0;
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
    const wired_srvloop_conn* c, int got_request, quic_obuf* out) {
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
    const wired_srvloop_conn* c, int got_request, quic_obuf* out) {
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
    const wired_srvloop_conn* c, int got_request, quic_obuf* out) {
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
static int emit_response(const wired_srvloop_conn* c, quic_obuf* out) {
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
 * re-emitted yet the client's 1-RTT packet is still acknowledged. Only sent
 * when the delayed-ACK policy actually calls for one now (RFC 9000
 * 13.2.1/13.2.2) -- unlike the piggyback callers above, this packet exists
 * solely to carry the ACK, so the delay window matters here. */
static int emit_ack_only(const wired_srvloop_conn* c, quic_obuf* out) {
  u8  pl[288]; /* room for QUIC_ACK_MAX_RANGES ranges, not just one pn */
  usz a = app_ack_append_if_due(c->l, pl, sizeof pl);
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
    const wired_srvloop_conn* c, int got_request, quic_obuf* out) {
  if (got_request) return emit_response(c, out);
  return emit_ack_only(c, out);
}

/* RFC 9000 12.2 / RFC 9114 6.2.1: emit the confirmation — a Handshake ACK plus
 * one 1-RTT packet that carries SETTINGS + HANDSHAKE_DONE and, when this
 * datagram also carried a GET, the 200 in the SAME 1-RTT payload (short-header
 * packets cannot coalesce). So curl receives SETTINGS to establish HTTP/3 and
 * the 200 together, never the 200 alone with SETTINGS still missing. */
static int emit_confirm_then_maybe_200(
    const wired_srvloop_conn* c, int got_request, quic_obuf* out) {
  if (!emit_confirm(c, got_request, out)) return 0;
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
    const wired_srvloop_conn* conn, int got_request, quic_obuf* out) {
  if (confirm_pending(conn->l))
    return emit_confirm_then_maybe_200(conn, got_request, out);
  return produce_confirmed(conn, got_request, out);
}

int wired_srvloop_reconfirm(const wired_srvloop_conn* conn, quic_obuf* out) {
  wired_srvloop* l = conn->l;
  if (!l->hs_done_sent || l->confirm_frames_len == 0) return 0;
  wired_srvloop_send_in sin = {
      quic_span_of(l->cli_scid, l->cli_scid_len), l->tx_pn++, -1,
      quic_span_of(l->confirm_frames, l->confirm_frames_len), 0};
  return wired_srvloop_send_onertt(conn->s, &sin, out);
}
