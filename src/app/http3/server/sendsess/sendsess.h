#ifndef WIRED_SENDSESS_SENDSESS_H
#define WIRED_SENDSESS_SENDSESS_H

#include "app/http3/server/sendq/sendq.h"

/** @file
 * One in-flight multi-packet response: a sendq of unsent slices, a log of
 * sent-but-unacknowledged slices keyed by packet number, and a requeue of
 * slices that must be retransmitted (RFC 9002 6: acknowledgement-driven
 * delivery). Pure bookkeeping — sealing and sending stay with the caller. */

/** Slices tracked at once (in flight or awaiting requeue). */
#define WIRED_SENDSESS_LOG 32

/** One sent slice awaiting acknowledgement. */
typedef struct {
  u64               pn;       /**< packet number it went out with */
  wired_sendq_slice sl;       /**< the slice itself */
  int               inflight; /**< 1 until acked (or moved to requeue) */
  u64               sent_ms;  /**< monotonic send time (congestion input) */
} wired_sent_slice;

typedef struct {
  wired_sendq       q;      /**< unsent tail of the response stream */
  int               active; /**< 1 while a response is being delivered */
  wired_sent_slice  log[WIRED_SENDSESS_LOG];     /**< sent, not yet acked */
  wired_sendq_slice requeue[WIRED_SENDSESS_LOG]; /**< to retransmit */
  usz               requeue_n;     /**< entries pending in requeue */
  u64               largest_acked; /**< highest pn the peer acked (monotone) */
  int               has_acked;     /**< 1 once any ACK arrived */
  int               pto_count;     /**< probes fired since the last ACK */
} wired_sendsess;

/** Arm the session over a full response byte stream (borrowed; must stay
 * alive until wired_sendsess_done).
 * @param s the session
 * @param stream response bytes (STREAM payload, HEADERS+DATA already framed)
 * @param len byte count at stream
 * @param chunk max stream bytes per packet */
void wired_sendsess_arm(
    wired_sendsess* s, const u8* stream, usz len, usz chunk);

/** @return slices currently in flight (sent, unacknowledged). */
usz wired_sendsess_inflight(const wired_sendsess* s);

/** Take the next slice to transmit: a requeued (lost) slice first, else the
 * next unsent one.
 * @return 1 with *out filled, 0 if nothing is ready to send. */
int wired_sendsess_take(wired_sendsess* s, wired_sendq_slice* out);

/** Record that slice sl went out as packet pn at now_ms (fills a log slot).
 * @return 1, or 0 if the log is full (the caller should stop transmitting
 *   until acknowledgements drain it). */
int wired_sendsess_sent(
    wired_sendsess* s, const wired_sendq_slice* sl, u64 pn, u64 now_ms);

/** Stream bytes currently in flight (congestion-window occupancy). */
usz wired_sendsess_inflight_bytes(const wired_sendsess* s);

/** Bytes an ACK of [lo, hi] would newly acknowledge, without consuming it.
 * @param s the session
 * @param lo lowest packet number in the range
 * @param hi highest packet number in the range
 * @param newest_sent_ms receives the newest send time among the hits
 *   (untouched when the range hits nothing)
 * @return total stream bytes of the in-flight packets the range covers. */
usz wired_sendsess_peek_ack(
    const wired_sendsess* s, u64 lo, u64 hi, u64* newest_sent_ms);

/** Consume one ACK range [lo, hi]: every logged in-flight packet in the
 * range becomes acknowledged. Unknown packet numbers are ignored. */
void wired_sendsess_ack(wired_sendsess* s, u64 lo, u64 hi);

/** Declare every in-flight packet at least 3 below largest_acked lost
 * (RFC 9002 6.1.1 packet threshold) and move its slice to the requeue for
 * retransmission (which always uses a fresh packet number via
 * wired_sendsess_sent).
 * @param s the session
 * @param largest_acked highest packet number the peer has acknowledged
 * @param lost_pns receives the lost packet numbers (0 to skip reporting)
 * @param cap slots at lost_pns
 * @return slices newly declared lost. */
usz wired_sendsess_detect_lost(
    wired_sendsess* s, u64 largest_acked, u64* lost_pns, usz cap);

/** Fire one probe timeout (RFC 9002 6.2): requeue the oldest in-flight
 * slice so it retransmits with a fresh packet number and count the probe.
 * Any ACK resets the count (wired_sendsess_ack).
 * @param s the session
 * @param max probes allowed since the last ACK
 * @return 1 (probed, or nothing was in flight), 0 once the budget is spent —
 *   the caller should tear the connection down. */
int wired_sendsess_pto_fire(wired_sendsess* s, int max);

/** @return 1 once everything was sent and acknowledged (session finished);
 *   also clears active. Inactive sessions report 0. */
int wired_sendsess_done(wired_sendsess* s);

#endif
