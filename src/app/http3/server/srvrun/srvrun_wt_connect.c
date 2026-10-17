#include "app/http3/server/srvrun/srvrun_impl.h"

static usz  srvrun_wtsend_ring_live(const srvrun_wtsend* w);
static void srvrun_wtsend_ring_write(srvrun_wtsend* w, wired_span payload);

/* Ring occupancy: bytes of roundbuf still pinned by an unsent, in-flight,
 * or requeued slice. Everything below the floor is ACKed and reusable
 * (wired_sendsess_unacked_floor's contract). */
static usz srvrun_wtsend_ring_live(const srvrun_wtsend* w) {
  return w->sess.q.len - wired_sendsess_unacked_floor(&w->sess);
}

/* Copy one round into the ring at its logical end. A SLICE never crosses
 * the wrap (sendq clamps there), but a staged round may -- split the copy. */
static void srvrun_wtsend_ring_write(srvrun_wtsend* w, wired_span payload) {
  usz at    = w->sess.q.len % SRVRUN_WTSEND_BUF;
  usz tail  = SRVRUN_WTSEND_BUF - at;
  usz first = payload.n < tail ? payload.n : tail;
  bytes_memcpy(w->roundbuf + at, payload.p, first);
  bytes_memcpy(w->roundbuf, payload.p + first, payload.n - first);
}

/* Stage one accepted round: copy payload into the ring behind the bytes
 * already staged and extend the live sendsess over it -- the round starts
 * reaching the wire on the next pump pass, WITHOUT waiting for any earlier
 * round's ACK. Space reclaims continuously as the oldest bytes ACK
 * (srvrun_wtsend_ring_live), so bounded retention means "one buffer of
 * UNACKED bytes", not "one buffer per full-epoch ACK" -- a single straggler
 * packet no longer turns a loss spike into a burst of dropped rounds. 0
 * when the round does not fit the live window (the caller decides whether
 * to drop). fin ends the app's rounds: append_open drops, so the stream's
 * true last slice carries the wire FIN (srvrun_wt_slice_fin) and the slot
 * reaps once fully ACKed. */
int srvrun_wtsend_stage_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin) {
  if (srvrun_wtsend_epoch_acked(w)) srvrun_wtsend_epoch_reset(c, w);
  if (srvrun_wtsend_ring_live(w) + payload.n > SRVRUN_WTSEND_BUF) return 0;
  srvrun_wtsend_ring_write(w, payload);
  wired_sendsess_extend(&w->sess, payload.n);
  w->stream_off += payload.n;
  w->append_open = fin == 0;
  return 1;
}

/* 1 iff the round was accepted and staged; folds the two-step check so
 * wired_server_wt_stream_send stays inside the CCN gate. */
int srvrun_wtsend_accept_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin) {
  return srvrun_wtsend_appendable(w, payload.n) &&
         srvrun_wtsend_stage_round(c, w, payload, fin);
}

/* Session slot sidx's CONNECT-stream send slot: the one already open, else
 * a fresh wtsend slot armed empty at wt_connect_sent_len[sidx] -- the
 * response's own resp[] sendsess is freed once its 2xx is ACKed, so later
 * capsules ride their own slot, continuing the stream exactly where the 2xx
 * ended. Seeded with the peer's bidi_local credit (RFC 9000 18.2), the same
 * as a reply on any client-initiated stream. 0 when every slot is busy. */
srvrun_wtsend* srvrun_wt_connect_sender(srvrun_conn* c, int sidx) {
  u64            id = srvrun_wt_slot(c, sidx)->connect_stream_id;
  srvrun_wtsend* w  = srvrun_wtsend_find(c, id);
  if (w) return w;
  w = srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_bidi_local);
  if (!w) return 0;
  w->append_open = 1;
  w->stream_id   = id;
  w->stream_off  = c->wt_connect_sent_len[sidx];
  srvrun_wtsend_epoch_reset(c, w);
  return w;
}

int srvrun_send_wt_capsule(
    srvrun_conn* c, int sidx, wired_span capsule_bytes, u8 fin) {
  /* RFC 9297 3.2: in HTTP/3 the capsule data stream is the DATA frames'
   * payload (+16: the frame's worst-case Type + Length varints, RFC 9114
   * 7.1); every caller's capsule fits 16 + 4 + WTCAPSULE_CLOSE_MESSAGE_MAX. */
  u8             df[16 + 16 + 4 + WTCAPSULE_CLOSE_MESSAGE_MAX];
  wired_obuf     dfb = obuf_of(df, sizeof df);
  usz            n   = h3_frame_put(&dfb, H3_FRAME_DATA, capsule_bytes);
  srvrun_wtsend* w   = srvrun_wt_connect_sender(c, sidx);
  if (!w || !srvrun_wtsend_accept_round(c, w, wired_span_of(df, n), fin))
    return 0;
  c->wt_connect_sent_len[sidx] += n;
  return 1;
}

/* 1 iff w is a CONNECT-stream send slot still open for more bytes and not
 * yet asked for its FIN -- the one state a FIN may be requested in, and the
 * one a teardown may drop. */
int srvrun_wt_connect_finable(const srvrun_wtsend* w) {
  return srvrun_wtsend_open_slot(w) && !srvrun_wtsend_closing(w);
}

/* A session ending without its own WT_CLOSE_SESSION (connection teardown, a
 * CONNECT stream this server reset) abandons whatever its still-open
 * CONNECT-stream send slot holds; a slot already carrying or awaiting the
 * closing FIN (append_open 0, or srvrun_wt_connect_fin's bare FIN) stays
 * until it is ACKed and reaped. */
void srvrun_wt_connect_sender_drop(srvrun_conn* c, int sidx) {
  srvrun_wtsend* w =
      srvrun_wtsend_find(c, srvrun_wt_slot(c, sidx)->connect_stream_id);
  if (srvrun_wt_connect_finable(w)) w->in_use = 0;
}

/* 1 iff this rejected append was a live round refused only because the
 * pipeline is full (epoch buffer exhausted, or an oversized view round
 * still in flight) -- as opposed to a misuse rejection (unknown/closed
 * slot, empty round), so stat_wtsend_busy counts real drops only. */
int srvrun_wtsend_busy_reject(const srvrun_wtsend* w, usz len) {
  return srvrun_wtsend_open_slot(w) && len != 0;
}

/* The flow-refused -1: count the drop where a live connection exists to
 * count it on (c is 0 when s resolves to no connection at all -- that
 * lookup failure shares the same refusal return). */
int srvrun_wtsend_flow_refuse(srvrun_conn* c) {
  if (c) c->stat_wtsend_flow++;
  return -1;
}
