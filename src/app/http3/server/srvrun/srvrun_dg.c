#include "app/http3/server/srvrun/srvrun_impl.h"

static int wt_session_delivers_directly(const wired_wt_session* s);
static int srvrun_dg_should_deliver(
    const srvrun_cfg* cfg, const wired_wt_session* s);
static u64 srvrun_dg_stream_limit_base(const srvrun_cfg* cfg);
static u64 srvrun_dg_stream_limit(const srvrun_cfg* cfg, const srvrun_conn* c);
static int srvrun_dg_id_exceeds_limit(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 connect_id);
static void srvrun_abort_unknown_dg_request(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 connect_id);
static int wt_session_receive_side_closed(const wired_wt_session* s);

/* One wt_streams slot's per-step work: offer it to the session if this step
 * (or an earlier one) claimed it but has not yet offered it, deliver any new
 * contiguous bytes to the app callback, slide the receive window forward once
 * everything contiguous has been delivered (making room for more), then reap
 * the slot if its FIN has now been fully delivered — split out of
 * srvrun_offer_wt_streams so the loop itself stays at the CCN gate. */
void srvrun_offer_and_deliver_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  int sidx;
  if (srvrun_wt_slot_needs_offer(slot)) {
    srvrun_offer_wt_slot(cfg, c, slot);
  }
  if (!slot->in_use) {
    return;
  }
  sidx = srvrun_wt_stream_owner(c, slot->offered, slot->wt_session_slot);
  srvrun_wt_rx rx = {slot->stream_id,     slot->buf,     &slot->win,
                     slot->fin,           slot->fin_off, &slot->delivered_len,
                     &slot->fin_delivered};
  srvrun_deliver_wt_stream_delta(cfg, c, sidx, &rx);
  wired_srvloop_wt_window_slide(
      &slot->win, slot->buf, sizeof slot->buf, slot->delivered_len);
  srvrun_reap_wt_slot(c, slot);
}

/* draft-ietf-webtrans-http3-15 4.3: after a step has reassembled this
 * datagram's frames into c->l.wt_streams[], run srvrun_offer_and_deliver_wt_
 * slot over every slot. */
void srvrun_offer_wt_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    srvrun_offer_and_deliver_wt_slot(cfg, c, &c->l.wt_streams[i]);
  }
}

/* RFC 9297 2.1: close the connection with H3_DATAGRAM_ERROR because a
 * received HTTP Datagram's Quarter Stream ID field was truncated/missing or
 * exceeded 2^60-1 (wired_wtwire_qsid_take rejects both the same way). */
void srvrun_close_on_bad_qsid(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "bad HTTP Datagram Quarter Stream ID";
  srvrun_send_app_close(
      cfg, c, H3_DATAGRAM_ERROR, wired_span_of(reason, sizeof reason - 1));
}

/* RFC 9297 2.1 (9297-009): a datagram naming a not-yet-established session is
 * buffered (wired_wt_session_offer_datagram, session.h) rather than delivered
 * -- the app callback only fires once the session has associated it directly
 * (established or draining), never while it merely sits in the
 * pre-establishment buffer. Checked BEFORE offer_datagram runs, since offer_
 * datagram's own return (1) does not distinguish "buffered" from
 * "associated". */
static int wt_session_delivers_directly(const wired_wt_session* s) {
  return s->state != WIRED_WT_UNESTABLISHED;
}

/* RFC 9297 2.1 (9297-007): "HTTP/3 Datagrams MUST NOT be sent unless the
 * corresponding stream's send side is open." A WT session's CONNECT stream
 * (its identity, session.h) has the server's send side open exactly while
 * the session is ESTABLISHED or DRAINING -- not yet (UNESTABLISHED, no 2xx
 * sent, also 9297-001's own gate) and not anymore (CLOSED: the CONNECT
 * stream itself closed, session.h's wired_wt_session_close doc). */
int srvrun_wt_session_send_side_open(const wired_wt_session* s) {
  return s->state == WIRED_WT_ESTABLISHED || s->state == WIRED_WT_DRAINING;
}

/* RFC 9221 5 / draft-ietf-webtrans-http3-15 SS4 (Phase 7b Slice 2): route one
 * queued received DATAGRAM's post-prefix bytes to the session whose OWN
 * connect_stream_id equals connect_id (srvrun_wt_slot_by_connect_id) rather
 * than to whichever session happens to be active most recently -- with
 * SRVRUN_MAX_WT_SESSIONS > 1 concurrent sessions, the two are not the same
 * slot. Still calls offer_datagram unconditionally so the session's own state
 * (buffered-vs-associated) stays consistent regardless of whether an app
 * callback is registered; the callback itself only fires when wt_session_
 * delivers_directly says the datagram was associated, not merely buffered
 * (9297-009). Split out of srvrun_deliver_rx_datagram so its own branch count
 * stays at the CCN gate. */
static int srvrun_dg_should_deliver(
    const srvrun_cfg* cfg, const wired_wt_session* s) {
  return wt_session_delivers_directly(s) && cfg->wt_on_datagram != 0;
}

/* Same transport-parameter-or-default computation as srvrun_stream_limit_base,
 * but from cfg alone (this call site has no srvrun_step_ctx). */
static u64 srvrun_dg_stream_limit_base(const srvrun_cfg* cfg) {
  u64 configured = cfg->id ? cfg->id->max_streams_bidi : 0;
  return configured ? configured : STP_DEFAULT_MAX_STREAMS_BIDI;
}

/* RFC 9297 2.1 (9297-010): the client-initiated bidi stream limit last
 * advertised via MAX_STREAMS, falling back to the transport-parameter
 * default before any raise -- same base-or-advertised pattern as
 * srvrun_grant_streams. */
static u64 srvrun_dg_stream_limit(const srvrun_cfg* cfg, const srvrun_conn* c) {
  u64 base = srvrun_dg_stream_limit_base(cfg);
  return c->stream_limit_advertised ? c->stream_limit_advertised : base;
}

/* RFC 9297 2.1 (9297-010): connect_id names a client-initiated bidi stream
 * (RFC 9000 2.1, id = 4*n) beyond the limit this connection has advertised
 * -- such a stream can never legally be opened by the client, so a
 * datagram naming it is distinguished from the ordinary "no session yet"
 * case below. */
static int srvrun_dg_id_exceeds_limit(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 connect_id) {
  return connect_id / 4 >= srvrun_dg_stream_limit(cfg, c);
}

/* RFC 9297 2 (9297-002): "If an HTTP Datagram is received and it is
 * associated with a request that has no known semantics for HTTP Datagrams,
 * the receiver MUST terminate the request. If HTTP/3 is in use, the request
 * stream MUST be aborted with H3_DATAGRAM_ERROR (0x33)." A connect_id with no
 * matching active WT session slot names exactly such a request -- this SDK's
 * only HTTP Datagram semantics are WebTransport's, so a Quarter Stream ID
 * that does not resolve to a live WebTransport session is a request this
 * server never assigned any HTTP Datagram meaning to. connect_id doubles as
 * the request stream id (wired_wtwire_qsid_take already multiplies the parsed
 * quarter back by 4), so it is aborted directly with the same RESET_STREAM
 * + STOP_SENDING pair srvrun_reject_wt_slot uses for a different rejection
 * reason -- UNLESS connect_id names a stream beyond the advertised
 * MAX_STREAMS limit (9297-010), which RFC 9297 2.1 calls out as its own
 * H3_ID_ERROR case since such a stream could never have been created at
 * all. */
static void srvrun_abort_unknown_dg_request(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 connect_id) {
  u64 err = srvrun_dg_id_exceeds_limit(cfg, c, connect_id) ? H3_ID_ERROR
                                                           : H3_DATAGRAM_ERROR;
  srvrun_send_wt_busy_reset(cfg, c, connect_id, err);
}

/* RFC 9297 2.1 (9297-008): "If a datagram is received after the
 * corresponding stream's receive side is closed, the received datagrams MUST
 * be silently dropped." A WT session's CONNECT stream closes both directions
 * at once (session.h's wired_wt_session_close doc), so WIRED_WT_CLOSED is
 * exactly "receive side closed" here. */
static int wt_session_receive_side_closed(const wired_wt_session* s) {
  return s->state == WIRED_WT_CLOSED;
}

/* The known-session half of srvrun_route_rx_datagram, split out so the
 * dispatcher itself stays at the CCN gate: s is a session a live slot
 * resolved to (never NULL), already past the unknown-semantics and
 * receive-side-closed checks. */
void srvrun_deliver_to_known_session(
    const srvrun_cfg* cfg, wired_wt_session* s, wired_span data) {
  int deliver = srvrun_dg_should_deliver(cfg, s);
  cfg->env->wt_usage.datagrams++;
  wired_wt_session_offer_datagram(s, data);
  if (deliver) {
    cfg->wt_on_datagram(cfg->wt_datagram_ctx, s, data);
  }
}

void srvrun_route_rx_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 connect_id, wired_span data) {
  int               sidx = srvrun_wt_slot_by_connect_id(c, connect_id);
  wired_wt_session* s;
  if (sidx < 0) {
    srvrun_abort_unknown_dg_request(cfg, c, connect_id);
    return;
  }
  s = srvrun_wt_slot(c, sidx);
  if (wt_session_receive_side_closed(s)) {
    return;
  }
  srvrun_deliver_to_known_session(cfg, s, data);
}
