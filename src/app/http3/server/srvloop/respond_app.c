#include "app/http3/server/srvloop/respond_impl.h"
#include "common/bytes/util/num.h"

static int       app_ack_due(const wired_srvloop* l);
static int       app_ack_ecn_any_seen(const wired_srvloop* l);
static void      app_ack_set_ecn(const wired_srvloop* l, ack_frame* f);
static usz       app_ack_encode_ranges(wired_srvloop* l, u8* buf, usz cap);
static usz       app_ack_kept(const ack_frame* f, u64 floor1);
static void      app_ack_prune(ack_frame* f, u64 floor1);
static const u8* build_body(
    wired_srvloop* l, u8* body, usz* body_len, const char** content_type);

/* RFC 9000 13.2.1/13.2.2/19.3: whether an ACK is owed on the App pn space
 * right now (ackpolicy, already latched by srvloop.c's receive path). */
static int app_ack_due(const wired_srvloop* l) {
  return ackpolicy_should_ack(
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
static void app_ack_set_ecn(const wired_srvloop* l, ack_frame* f) {
  if (!app_ack_ecn_any_seen(l)) {
    return;
  }
  f->has_ecn = 1;
  f->ect0    = l->ecn_ect0;
  f->ect1    = l->ecn_ect1;
  f->ce      = l->ecn_ce;
}

/* Ranges descend, so the ones still worth reporting -- any part at or
 * above floor1 -- are a prefix; range 0 (the largest) always stays. */
static usz app_ack_kept(const ack_frame* f, u64 floor1) {
  usz n = 1;
  while (n < f->n_ranges && f->ranges[n].hi >= floor1) {
    n++;
  }
  return n;
}

/* RFC 9000 13.2.3: drop what the peer already knows we received -- packets
 * below floor1 (1 + the Largest Acknowledged of our acknowledged ACKs). */
static void app_ack_prune(ack_frame* f, u64 floor1) {
  ack_range* last;
  f->n_ranges = app_ack_kept(f, floor1);
  last        = &f->ranges[f->n_ranges - 1];
  if (last->lo < floor1 && last->hi >= floor1) {
    last->lo = floor1;
  }
}

/* RFC 9000 19.3: encode a full multi-range ACK frame from the App pn
 * space's received-pn window (pnspaces_recv, RFC 9000 12.3/13.2.1),
 * with an ack_delay reflecting how long the oldest unacked eliciting packet
 * has waited (ack_delay_encode, RFC 9000 19.3/13.2.5), and this
 * connection's cumulative ECN counts (RFC 9000 19.3.2, app_ack_set_ecn).
 * Returns the encoded length, 0 if the window is empty or encoding fails
 * (e.g. the range count would overflow ACK_MAX_RANGES -- caller then
 * sends no ACK this round rather than a corrupt one). */
static usz app_ack_encode_ranges(wired_srvloop* l, u8* buf, usz cap) {
  u64       raw[2 * ACK_MAX_RANGES + 1];
  u64       largest;
  u64obuf   ranges = {raw, sizeof raw / sizeof raw[0], 0};
  ack_frame f      = {0};
  if (!pnspaces_ack_ranges(
          &l->ack_recv, PNS_APP, &(pnspaces_ack_out){&largest, &ranges})) {
    return 0;
  }
  /* RFC 9000 13.2.4: past ACK_MAX_RANGES ranges, send the newest ones
   * rather than no ACK at all (2k-1 raw entries = k ranges) */
  if (!ackrangeconv_to_frame(
          largest, raw, u64_min(ranges.len, 2 * ACK_MAX_RANGES - 1), &f)) {
    return 0;
  }
  app_ack_prune(&f, l->ack_floor1);
  f.ack_delay = ack_delay_encode(
      (l->now_ms - l->app_ack_policy.since_tick) * 1000,
      ACK_DELAY_EXPONENT_DEFAULT);
  app_ack_set_ecn(l, &f);
  return ack_encode(buf, cap, &f);
}

/* RFC 9000 13.2.1: append a multi-range ACK of the App pn space's received
 * packets to a 1-RTT payload that already carries other data (confirmation
 * or a 200 response) -- piggybacking costs nothing extra on the wire, so
 * these paths always attach a pending ACK rather than waiting out the delay
 * window on a packet that's going out anyway. Nothing to append (the App
 * space's window is empty) is the only reason this returns 0. Clears the
 * pending state once encoded (ackpolicy_on_ack_sent) so the next
 * step's due-check starts fresh. */
usz srvloop_app_ack_append(wired_srvloop* l, u8* buf, usz cap) {
  usz n = app_ack_encode_ranges(l, buf, cap);
  if (n) {
    ackpolicy_on_ack_sent(&l->app_ack_policy);
  }
  return n;
}

/* RFC 9000 13.2.1/13.2.2: append an ACK ONLY when one is actually due
 * (ackpolicy_should_ack) -- for srvloop_emit_ack_only's bare-ACK packet, where
 * sending one costs a whole extra packet on the wire, so the delay window
 * genuinely matters (unlike srvloop_app_ack_append's piggyback callers above).
 * Suppressed while ack_defer is set: the driving loop (srvrun.c) piggybacks
 * or flushes the pending ACK itself this step. */
usz srvloop_app_ack_append_if_due(wired_srvloop* l, u8* buf, usz cap) {
  if (l->ack_defer) {
    return 0;
  }
  if (!app_ack_due(l)) {
    return 0;
  }
  return srvloop_app_ack_append(l, buf, cap);
}

usz wired_srvloop_ack_peek(wired_srvloop* l, u8* buf, usz cap) {
  if (!l->app_ack_policy.pending) {
    return 0;
  }
  return app_ack_encode_ranges(l, buf, cap);
}

void wired_srvloop_ack_mark_sent(wired_srvloop* l) {
  ackpolicy_on_ack_sent(&l->app_ack_policy);
}

/* RFC 9110 9.3: ask the registered handler to build the response body for the
 * decoded request. No handler (or it declines) -> a body-less 200. The body is
 * written into the caller's buffer; *body_len is 0 when there is none.
 * *content_type is left at its caller-supplied value (0) unless the handler
 * sets it. */
static const u8* build_body(
    wired_srvloop* l, u8* body, usz* body_len, const char** content_type) {
  wired_obuf ob         = obuf_of(body, WIRED_SRVLOOP_BODY_MAX);
  int        more       = 0;
  u64        total_size = 0;
  *body_len             = 0;
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
int srvloop_response_frame(wired_srvloop* l, int got_request, wired_obuf* out) {
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
        {200, wired_span_of(b, body_len), content_type}};
    return wired_h3srv_build_response(&l->h3, &send, out);
  }
}

/* RFC 9000 12.2 / 19.4: a short-header (1-RTT) packet carries no length and
 * must be the datagram's last packet, so the confirmation and a coalesced 200
 * cannot be two separate 1-RTT packets — they share ONE payload. SETTINGS +
 * HANDSHAKE_DONE come first (srvloop_build_settings_frame must mark SETTINGS
 * sent before the 200 may be built), then the 200 STREAM when a GET was
 * decoded; otherwise the payload is the confirmation alone. Frame order within
 * a packet does not constrain HTTP/3 stream order, so a peer routes each STREAM
 * by its id. */
int srvloop_confirm_then_maybe_200(
    const wired_srvloop_conn* c, int got_request, wired_obuf* out) {
  wired_obuf ob = obuf_of(out->p, out->cap);
  usz        a;
  if (!srvloop_confirm_payload(c, &ob)) {
    return 0;
  }
  a  = ob.len;
  ob = obuf_of(out->p + a, out->cap - a);
  if (!srvloop_response_frame(c->l, got_request, &ob)) {
    return 0;
  }
  out->len = a + ob.len;
  return 1;
}
