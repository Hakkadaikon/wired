#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_cwnd_has_room(const srvrun_conn* c);
static int srvrun_cwnd_fits(const srvrun_conn* c);
static usz srvrun_wtsend_consumed_bytes(const srvrun_conn* c);
static int srvrun_sess_credit_room(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit);
static void srvrun_stream_credit_raise(u64* credit, u64 value);

/* Sum of in-flight stream bytes across every resp[] AND wtsend slot -- the
 * congestion window (RFC 9002 7) gates the connection's TOTAL in-flight,
 * not any one stream's. */
usz srvrun_inflight_bytes_all(const srvrun_conn* c) {
  usz total = srvrun_wtsend_inflight_bytes(c);
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      total += wired_sendsess_inflight_bytes(&c->resp[i].sess);
    }
  }
  return total;
}

/* 1 when sess's send log has a free entry. The log gate applies to every
 * send regardless of cwnd: a slice taken and sent while the log is full can
 * be recorded in neither log nor requeue -- if that packet then drops, the
 * stream has a permanent hole the peer waits on forever. */
int srvrun_sess_log_room(const wired_sendsess* sess) {
  return wired_sendsess_inflight(sess) < WIRED_SENDSESS_LOG;
}

/* 1 when the connection's congestion window (RFC 9002 7) has room for one
 * more chunk across every slot combined. Pacing (RFC 9002 7.7) is NOT
 * checked here -- it gates whole round-robin passes
 * (srvrun_pump_round_gated), not individual slots. Reads the cached total
 * (srvrun_conn.acct_inflight) rather than re-walking every slot per slice,
 * plus the non-STREAM packets in flight (srvrun_bytes_in_flight). RFC 9002
 * 7.5: a PTO probe (probe_n) is not blocked by it. */
static int srvrun_cwnd_has_room(const srvrun_conn* c) {
  return c->l.ackst.probe_n || srvrun_cwnd_fits(c);
}

/* 1 when the window itself has room for one more chunk. */
static int srvrun_cwnd_fits(const srvrun_conn* c) {
  return srvrun_bytes_in_flight(c) + srvrun_mps(c) <= c->cc.cwnd;
}

/* RFC 9002 7.8: after a send pass the window is underutilized when it
 * still has room and pacing did not end the pass -- a sender held back
 * only by pacing is not application limited (9002-071). */
void srvrun_note_app_limited(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  c->cc.app_limited = srvrun_pace_ok(ctx, c) && srvrun_cwnd_fits(c);
}

/* Sum of consumed (taken-from-sendq) stream bytes across every WT send
 * slot -- the wtsend side of srvrun_conn_consumed_bytes' fan-out. */
static usz srvrun_wtsend_consumed_bytes(const srvrun_conn* c) {
  usz total = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (c->wtsend[i].in_use) {
      total += c->wtsend[i].sess.stream_base_offset + c->wtsend[i].sess.q.cur;
    }
  }
  return total;
}

/* RFC 9000 4.1: sum of stream bytes already handed to wired_sendsess_take
 * (stream_base_offset + q.cur, the ABSOLUTE next-unsent offset -- q.cur
 * alone restarts on every streaming re-arm / epoch recycle) across every
 * resp[] AND wtsend slot -- the cumulative total the connection's ONE
 * conn_credit (initial_max_data + any MAX_DATA raises) bounds. A
 * retransmit reuses an offset range already counted here, so PTO/loss
 * resends never double-count (mirrors srvrun_inflight_bytes_all's per-slot
 * fan-out, but this quantity only grows -- it is not cleared by an ACK the
 * way in-flight bytes are). */
usz srvrun_conn_consumed_bytes(const srvrun_conn* c) {
  usz total = srvrun_wtsend_consumed_bytes(c);
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      total += c->resp[i].sess.stream_base_offset + c->resp[i].sess.q.cur;
    }
  }
  return total;
}

/* One sess's contribution to acct_consumed: the absolute next-unsent stream
 * offset (see srvrun_conn_consumed_bytes on why base + cur, not cur alone).
 */
usz srvrun_sess_consumed(const wired_sendsess* sess) {
  return sess->stream_base_offset + sess->q.cur;
}

/* Resync the cached totals from the full scans -- once per step (and per
 * pump pass), so ACK/requeue/reap/re-arm effects are picked up wholesale
 * instead of being tracked per event; see srvrun_conn.acct_inflight's doc.
 */
void srvrun_acct_resync(srvrun_conn* c) {
  c->acct_inflight = srvrun_inflight_bytes_all(c);
  c->acct_consumed = srvrun_conn_consumed_bytes(c);
}

/* 1 when the connection's send credit (RFC 9000 18.2/19.9) has room for one
 * more chunk, summed across every slot the same way cwnd is (cached total,
 * see srvrun_acct_resync). */
int srvrun_conn_credit_has_room(const srvrun_conn* c) {
  return c->acct_consumed + srvrun_mps(c) <= c->conn_credit;
}

/* RFC 9000 4.1: sess has unsent bytes and its stream credit has no room for
 * the next chunk (srvrun_sess_credit_room's stream half). */
int srvrun_stream_credit_blocked(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  return !wired_sendq_all_sent(&sess->q) &&
         sess->stream_base_offset + sess->q.cur + srvrun_mps(c) > credit;
}

/* 1 when RFC 9000 4.1's two flow-control credits (connection-wide, and
 * sess's own stream-level ceiling `credit`, RFC 9000 18.2/19.10) both have
 * room for one more chunk. Consumed bytes for one stream are exactly its
 * own sendq cursor (no cross-slot fan-out needed at this level). */
static int srvrun_sess_credit_room(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  /* stream_base_offset + q.cur is the ABSOLUTE next-unsent stream offset
   * (RFC 9000 19.10's limit is absolute): q.cur alone restarts at 0 on
   * every streaming re-arm / epoch recycle and would under-count. */
  return srvrun_conn_credit_has_room(c) &&
         sess->stream_base_offset + sess->q.cur + srvrun_mps(c) <= credit;
}

/* The log gate and both flow-control credits -- srvrun_can_send_new short
 * of the congestion window, which a PTO probe bypasses (RFC 9002 7.5). */
int srvrun_sess_flow_room(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  return srvrun_sess_log_room(sess) && srvrun_sess_credit_room(c, sess, credit);
}

/* 1 when a brand-new slice (from sess's sendq, not its requeue) may go out:
 * the log, cwnd, and both flow-control credit gates all apply. */
int srvrun_can_send_new(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  return srvrun_sess_log_room(sess) && srvrun_cwnd_has_room(c) &&
         srvrun_sess_credit_room(c, sess, credit);
}

/* RFC 9000 4.1/19.9: apply this step's highest-seen MAX_DATA (srvloop's
 * gather_max_data) to the connection's running send credit -- raise only,
 * per RFC 9000 4.1 ("MUST NOT reduce"), and always consume the step's
 * latch so a later step's absence of a new MAX_DATA is not mistaken for
 * this one's value persisting (srvloop.h's l->max_data_seen is this step's
 * observation only, not a running value itself). */
void srvrun_apply_conn_credit_update(srvrun_conn* c) {
  if (!c->l.max_data_seen_flag) {
    return;
  }
  if (c->l.max_data_seen > c->conn_credit) {
    c->conn_credit = c->l.max_data_seen;
  }
  c->l.max_data_seen_flag = 0;
}

/* Raise a stream credit ceiling to value if that is higher, RFC 9000 4.1's
 * raise-only rule -- split out so srvrun_apply_stream_credit_update's own
 * CCN stays at the gate. */
static void srvrun_stream_credit_raise(u64* credit, u64 value) {
  if (value > *credit) {
    *credit = value;
  }
}

/* w is claimed and sending on stream_id. */
int srvrun_wtsend_matches(const srvrun_wtsend* w, u64 stream_id) {
  return w->in_use && w->stream_id == stream_id;
}

/* The in-use WT send slot on stream_id, or 0 if none. */
srvrun_wtsend* srvrun_wtsend_find(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (srvrun_wtsend_matches(&c->wtsend[i], stream_id)) {
      return &c->wtsend[i];
    }
  }
  return 0;
}

/* Apply one this-step MAX_STREAM_DATA slot to its named resp[] or wtsend
 * slot's running stream credit. A stream_id naming no in-use slot (already
 * reaped, or never claimed) is a no-op -- srvloop has no notion of send
 * slots and cannot itself validate the id. */
void srvrun_apply_one_stream_credit_update(srvrun_conn* c, usz i) {
  srvrun_resp*   r = srvrun_resp_find(c, c->l.max_stream_data_stream_id[i]);
  srvrun_wtsend* w = srvrun_wtsend_find(c, c->l.max_stream_data_stream_id[i]);
  if (r) {
    srvrun_stream_credit_raise(
        &r->stream_credit, c->l.max_stream_data_value[i]);
  }
  if (w) {
    srvrun_stream_credit_raise(
        &w->stream_credit, c->l.max_stream_data_value[i]);
  }
}
