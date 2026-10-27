#include "app/http3/server/srvrun/srvrun_impl.h"

static usz srvrun_dg_room(const srvrun_conn* c, usz cap);
static int srvrun_dg_build(
    const srvrun_conn*    c,
    wired_span            data,
    const dgdeliver_opts* o,
    wired_obuf*           plb);
static int srvrun_send_dg_prefixed(
    const srvrun_cfg*       cfg,
    srvrun_conn*            c,
    const wired_wt_session* s,
    wired_span              payload,
    wired_obuf*             out);
static int srvrun_send_pending_dg_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int i, wired_obuf* out);
static int srvrun_send_pending_dg_head(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out);

/* RFC 9221 5 / RFC 9000 14: the plaintext room one DATAGRAM frame may take
 * -- the validated probe's whole plaintext (srvrun_mps plus the STREAM header
 * it reserves), capped at the local buffer. A DATAGRAM cannot be split, so
 * one past this is refused instead of sent into a path that drops it. */
static usz srvrun_dg_room(const srvrun_conn* c, usz cap) {
  return (usz)u64_min(cap, srvrun_mps(c) + SRVRUN_STREAM_HDR_MAX);
}

/* Build the DATAGRAM frame into plb when the congestion window has room
 * for it (RFC 9221 5.4: DATAGRAM frames are congestion controlled; a
 * refused one is delayed by the pending queue, dropped by the ring). */
static int srvrun_dg_build(
    const srvrun_conn*    c,
    wired_span            data,
    const dgdeliver_opts* o,
    wired_obuf*           plb) {
  return dgdeliver_frame(data, o, plb) &&
         srvrun_bytes_in_flight(c) + plb->len <= c->cc.cwnd;
}

/* RFC 9221 5.4: 1 iff a DATAGRAM of len payload bytes cannot fit the
 * congestion window now (frame type + an 8-byte Length bound included). */
int srvrun_dg_cwnd_blocked(const srvrun_conn* c, usz len) {
  return srvrun_bytes_in_flight(c) + len + 9 > c->cc.cwnd;
}

/* Seal one QUIC DATAGRAM (RFC 9221 5) carrying data into a 1-RTT packet and
 * send it. Unlike srvrun_send_slice/srvrun_send_goaway, there is no
 * wired_sendsess/ACK-loss bookkeeping: RFC 9221 1 DATAGRAM frames are never
 * retransmitted. max_frame_size is the peer's advertised
 * max_datagram_frame_size (sdrv_recv_client_hello populated it from the
 * real ClientHello transport parameters): dgdeliver_frame's internal
 * datagram_allowed check rejects the send outright when the
 * peer never advertised support (value 0) or when the encoded frame would
 * exceed the peer's advertised limit. Shared by the single-slot pending
 * queue below and the session-addressed ring (srvrun_dgring_drain).
 * Returns 1 if sent, 0 if the frame could not be built (too large for the
 * peer's limit, or past the validated PMTU's room, srvrun_dg_room) or the
 * congestion window has no room for it (srvrun_dg_build). */
int srvrun_send_datagram_now(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span data, wired_obuf* out) {
  u8                    pl[1400];
  wired_obuf            plb        = obuf_of(pl, srvrun_dg_room(c, sizeof pl));
  u64                   peer_limit = c->s.sdrv.peer_max_datagram_frame_size;
  dgdeliver_opts        o = {.with_length = 1, .max_frame_size = peer_limit};
  wired_srvloop_send_in sin;
  if (!srvrun_dg_build(c, data, &o, &plb)) {
    return 0;
  }
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, plb.len),
      0,
      0,
      0,
      0};
  if (!srvloop_send_onertt_rec(&c->l, &c->s, &sin, out)) {
    return 0;
  }
  srvrun_send(cfg, c, wired_span_of(out->p, out->len), "DATAGRAM sent\n");
  return 1;
}

/* RFC 9297 2.1: on the wire every HTTP Datagram carries the quarter-stream-
 * id prefix of the session it belongs to. The pending slot stores the bare
 * payload (one slot serves every session on the connection), so the prefix
 * is applied here, per target session, at send time -- the exact mirror of
 * srvrun_deliver_rx_datagram stripping it on receive. A real browser peer
 * decodes the first payload byte as that prefix and silently drops the
 * datagram when it names no session it knows. */
static int srvrun_send_dg_prefixed(
    const srvrun_cfg*       cfg,
    srvrun_conn*            c,
    const wired_wt_session* s,
    wired_span              payload,
    wired_obuf*             out) {
  u8  buf[8 + sizeof c->dg_pending_buf[0]];
  usz qn = wtwire_qsid_put(buf, sizeof buf, s->connect_stream_id);
  if (!qn) {
    return 0;
  }
  bytes_memcpy(buf + qn, payload.p, payload.n);
  out->len = 0;
  return srvrun_send_datagram_now(
      cfg, c, wired_span_of(buf, qn + payload.n), out);
}

/* One session slot's share of srvrun_send_pending_datagram: an inactive or
 * send-side-closed slot is skipped (1 -- best-effort, mirroring
 * srvrun_broadcast_to_all), an eligible one reports its send result. */
static int srvrun_send_pending_dg_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int i, wired_obuf* out) {
  wired_wt_session* s;
  usz               h = c->dg_pending_head;
  if (!srvrun_wt_is_active(c, i)) {
    return 1;
  }
  s = srvrun_wt_slot(c, i);
  if (!srvrun_wt_session_send_side_open(s)) {
    return 1;
  }
  return srvrun_send_dg_prefixed(
      cfg, c, s, wired_span_of(c->dg_pending_buf[h], c->dg_pending_len[h]),
      out);
}

/* Seal c's one pending broadcast DATAGRAM (srvrun_queue_datagram's single
 * last-writer-wins slot) once per active WT session, each with its own
 * session's qsid prefix; clears c->dg_pending when every eligible session
 * was sent to, keeps it pending on failure so a later step may retry
 * against a raised peer limit. */
static int srvrun_send_pending_dg_head(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out) {
  int ok = 1;
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    ok &= srvrun_send_pending_dg_slot(cfg, c, i, out);
  }
  return ok;
}

/* Drain c's pending queue oldest first, each entry once per active WT
 * session with its own qsid prefix (srvrun_send_pending_dg_head). Stops at
 * the first entry that fails, keeping it (and the rest) pending so a later
 * step may retry against a raised peer limit. */
int srvrun_send_pending_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out) {
  while (c->dg_pending) {
    if (!srvrun_send_pending_dg_head(cfg, c, out)) {
      return 0;
    }
    c->dg_pending_head = (c->dg_pending_head + 1) % SRVRUN_DG_PENDING_Q;
    c->dg_pending--;
  }
  return 1;
}

/* 1 if c has any active WT session (any slot), regardless of which one. */
int srvrun_wt_any_active(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    if (srvrun_wt_is_active(c, i)) {
      return 1;
    }
  }
  return 0;
}
