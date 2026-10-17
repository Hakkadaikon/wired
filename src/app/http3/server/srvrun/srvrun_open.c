#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_open_qdec_stream(srvrun_conn* c);
static int  srvrun_qdec_send(srvrun_conn* c, wired_span p);
static int  wt_flow_allows_open(
    const wired_wt_session* s, int bidi, wired_span payload);
static int srvrun_wt_streams_blocked_owed(
    int sidx, const wired_wt_session* s, int bidi);
static u64 srvrun_wt_stream_limit(const wired_wt_session* s, int bidi);

/* RFC 9204 4.2 / RFC 9114 6.2: open the decoder stream once, beside the
 * encoder stream, over its 0x03 type byte, as soon as srvrun_qdec_open_due
 * allows (a busy wtsend table retries next step). */
static void srvrun_open_qdec_stream(srvrun_conn* c) {
  static const u8 type[] = {H3_STREAM_QPACK_DECODER};
  srvrun_wtsend*  w;
  if (!srvrun_qdec_open_due(c)) return;
  w = srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_uni);
  if (!w) return;
  w->append_open = 1;
  srvrun_wtsend_arm_id(c, w, SRVRUN_QDEC_STREAM, wired_span_of(type, 1));
  c->qdec_wtsend_slot   = (int)(w - c->wtsend);
  c->qdec_stream_opened = 1;
}

/* RFC 9114 6.2 / RFC 9204 4.2: open the QPACK encoder and decoder streams
 * once SETTINGS is sent; raw QUIC never sends it and opens neither. */
void srvrun_open_qpack_streams(srvrun_conn* c) {
  if (!c->l.h3.settings_sent) return;
  srvrun_open_qenc_stream(c);
  srvrun_open_qdec_stream(c);
}

/* The wtsend slot a QPACK stream was opened on, re-checked against the
 * stream id it was opened for: 0 when the stream is not open, or the slot
 * no longer holds it (freed, or claimed by another stream since). */
srvrun_wtsend* srvrun_plumbing_wtsend(
    srvrun_conn* c, int opened, int slot, u64 stream_id) {
  srvrun_wtsend* w = &c->wtsend[slot];
  if (!opened) return 0;
  return srvrun_wtsend_matches(w, stream_id) ? w : 0;
}

/* Append p to the decoder stream; 0 (still owed) until it is open or while
 * its send ring is full. */
static int srvrun_qdec_send(srvrun_conn* c, wired_span p) {
  srvrun_wtsend* w = srvrun_plumbing_wtsend(
      c, c->qdec_stream_opened, c->qdec_wtsend_slot, SRVRUN_QDEC_STREAM);
  return w ? srvrun_wtsend_stage_round(c, w, p, 0) : 0;
}

/* RFC 9204 4.4: send what this decoder owes (Section Acknowledgments, then
 * an Insert Count Increment) after the step applied the peer's encoder
 * stream and decoded its sections; unsent bytes stay owed for a later
 * step. */
void srvrun_flush_qdec(srvrun_conn* c) {
  u8         b[QDYN_DEC_OUT_MAX];
  wired_obuf ob      = obuf_of(b, sizeof b);
  u64        inserts = c->l.h3.qdyn.dropped + c->l.h3.qdyn.count;
  if (!qdyn_dec_pending(&c->l.h3.qdec, inserts, &ob)) return;
  if (srvrun_qdec_send(c, wired_span_of(b, ob.len)))
    qdyn_dec_sent(&c->l.h3.qdec, inserts);
}

/* 1 iff opening one more stream of the given direction AND sending
 * payload.n bytes of Stream Body on it both stay within the session's
 * own limits (wired_wt_session_stream_open_allowed/data_send_allowed,
 * session.h). Folded into one predicate so every caller's own branch count
 * stays at the CCN gate. */
static int wt_flow_allows_open(
    const wired_wt_session* s, int bidi, wired_span payload) {
  return wired_wt_session_stream_open_allowed(s, bidi) &&
         wired_wt_session_data_send_allowed(s, payload.n);
}

/* s's own slot index on c, or -1 for a not-yet-resolved connection (c == 0)
 * as well as an unowned session -- lets every srvrun_wt_open_flow_ok caller
 * pass srvrun_session_conn's possibly-null result straight through without its
 * own null guard. */
int srvrun_wt_session_slot_or_absent(srvrun_conn* c, wired_wt_session* s) {
  return c ? srvrun_conn_session_slot(c, s) : -1;
}

/* draft-ietf-webtrans-http3-15 SS5.3/SS5.4 (WTH3-058/WTH3-061): 1 iff sidx
 * names a real slot (the owning connection is live and owns s) AND opening
 * one more stream of the given direction with payload.n bytes of Stream Body
 * stays within whichever peer-advertised WT_MAX_STREAMS/WT_MAX_DATA limits
 * are currently in force (wt_flow_allows_open -- a limit of 0 means "no
 * capsule received yet", which both predicates already treat as "allowed",
 * so a session that never opted into flow control is never gated here). A
 * sender must simply not exceed the peer's limits, so an over-limit open is
 * refused and nothing else happens: the session stays established, and the
 * same open succeeds once the peer raises the limit with a WT_MAX_DATA/
 * WT_MAX_STREAMS capsule (srvrun_wt_rx_capsules). Only a RECEIVER closes on
 * the PEER's violation. @param sidx srvrun_wt_session_slot_or_absent's result
 */
int srvrun_wt_open_flow_ok(
    int sidx, wired_wt_session* s, int bidi, wired_span payload) {
  return sidx >= 0 && wt_flow_allows_open(s, bidi, payload);
}

/* 1 iff a WT_STREAMS_BLOCKED notification is owed: sidx names a real slot
 * AND the session-level stream-count limit (not the data limit, not the
 * peer's QUIC-level uni-stream grant) is what refused the open. */
static int srvrun_wt_streams_blocked_owed(
    int sidx, const wired_wt_session* s, int bidi) {
  return sidx >= 0 && !wired_wt_session_stream_open_allowed(s, bidi);
}

/* The current WT_MAX_STREAMS limit for the given direction, straight off
 * the session's own public field (session.h) -- shares the bidi ? ... : ...
 * choice so srvrun_wt_notify_streams_blocked's own branch count stays at
 * the CCN gate. */
static u64 srvrun_wt_stream_limit(const wired_wt_session* s, int bidi) {
  return bidi ? s->max_streams_bidi : s->max_streams_uni;
}

/* draft-ietf-webtrans-http3-16 SS5.3/SS5.6.3 (WTH3-059): the WT_STREAMS_
 * BLOCKED capsule a server-initiated open sends when refused specifically by
 * the session-level stream-count limit -- not by the data limit or the
 * peer's QUIC-level uni-stream grant, which this is never sent for (RFC
 * 9000's own STREAMS_BLOCKED, srvrun_notify_uni_blocked, already covers
 * that case). srvrun_send_wt_capsule's own best-effort return is not
 * checked -- a lost hint costs nothing the peer's own retry does not
 * already recover from (unlike a flow-control-raising capsule, this is
 * advisory, SS5.3). */
void srvrun_wt_notify_streams_blocked(
    srvrun_conn* c, int sidx, const wired_wt_session* s, int bidi) {
  u8         body[16];
  wired_obuf bob = obuf_of(body, sizeof body);
  u64        lim = srvrun_wt_stream_limit(s, bidi);
  if (!srvrun_wt_streams_blocked_owed(sidx, s, bidi)) return;
  if (!wtcapsule_encode_streams_blocked(&bob, bidi, lim)) return;
  srvrun_send_wt_capsule(c, sidx, wired_span_of(body, bob.len), 0);
}

/* 1 iff c's own server-initiated uni-stream grant (peer_uni_stream_limit)
 * admits one more open; latches uni_blocked_seen on refusal so the next
 * srvrun_pump_sess pass sends a STREAMS_BLOCKED(uni) (srvrun_notify_uni_
 * blocked's own doc -- this call site has no srvrun_cfg to send through). */
int srvrun_wt_uni_grant_ok(srvrun_conn* c) {
  if (srvrun_uni_open_allowed(c)) return 1;
  c->uni_blocked_seen = 1;
  return 0;
}
