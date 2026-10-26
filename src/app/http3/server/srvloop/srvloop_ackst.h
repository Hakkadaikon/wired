#ifndef WIRED_SRVLOOP_SRVLOOP_ACKST_H
#define WIRED_SRVLOOP_SRVLOOP_ACKST_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/detect/recovery/ackpolicy.h"
#include "transport/recovery/rtx/sentmeta/record.h"

/** Sent packets carrying an ACK frame remembered for RFC 9000 13.2.3's
 * range pruning (srvloop_ackst.ackd_pn1); the oldest is overwritten. */
#define WIRED_SRVLOOP_ACKD 8

/** The sent-packet record and ACK state loss recovery reads and the
 * receive path keeps. */
typedef struct {
  /** RFC 9002 A.1: every 1-RTT packet sealed through
   * srvloop_send_onertt_rec (pn, now_ms, ack-eliciting, size), until the
   * peer acknowledges it or it is declared lost. total_in_flight counts the
   * in-flight ones (RFC 9002 2), less a STREAM slice's own bytes, which the
   * driving loop's send sessions count instead (sentmeta_uncount). */
  sentmeta  sent;
  ackpolicy hs_ack_policy; /**< Handshake space's delayed-ACK timer */
  /** When 1, respond.c's bare-ACK packet (emit_ack_only) is suppressed for
   * the current step: the driving loop (srvrun.c) piggybacks the pending
   * App-space ACK onto the response slice it is about to send, or flushes
   * it itself at step end if no slice went out. A caller that never sets
   * it (0, every plain srvloop user) keeps the original behavior. */
  u8 ack_defer;
  /** RFC 9002 5.1/5.3: the Largest Acknowledged of the step's ACK frame
   * with the largest Largest Acknowledged -- the one frame an RTT sample
   * may come from (also the highest ack_hi). Valid while
   * wired_srvloop.ack_n > 0. */
  u64 largest;
  /** That frame's ACK Delay field, in units of 2^ack_delay_exponent us. */
  u64 delay_raw;
  /** RFC 9000 13.2.1: 1 when the packet just numbered (app_rx_pn) skipped
   * at least one packet number past the largest received before it. */
  u8 rx_gap;
  /** RFC 9000 13.2.1: 1 while the datagram being stepped was ECN-CE marked
   * (wired_srvloop_ecn_note). */
  u8 rx_ce;
  /** RFC 9000 13.2.3: 1 + the pn of a recent packet that carried an ACK
   * frame, 0 = free. */
  u64 ackd_pn1[WIRED_SRVLOOP_ACKD];
  /** Each remembered ACK frame's Largest Acknowledged. */
  u64 ackd_largest[WIRED_SRVLOOP_ACKD];
  /** The ackd slot the next ACK-carrying packet overwrites. */
  u8 ackd_next;
  /** RFC 9000 13.2.3: 1 + the largest Largest Acknowledged of our ACK
   * frames the peer has acknowledged (0 = none) -- packets below it no
   * longer need reporting. */
  u64 floor1;
  /** RFC 9002 A.8 time_of_last_ack_eliciting_packet for the 1-RTT space:
   * now_ms of the latest ack-eliciting srvloop_send_onertt_rec. */
  u64 last_elicit_ms;
  /** RFC 9002 7.5: PTO probe packets still allowed past the congestion
   * window and pacing; each ack-eliciting send uses one. 0 outside a PTO. */
  u8 probe_n;
  /** RFC 9002 A.8/A.9 pto_count of the 1-RTT space: probes fired since the
   * last newly acknowledged packet; scales the PTO backoff. */
  int pto_count;
} srvloop_ackst;

#endif
