#ifndef WIRED_SRVLOOP_SRVLOOP_SENT_H
#define WIRED_SRVLOOP_SRVLOOP_SENT_H

#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvloop/srvloop_wt.h"

/** wired_srvloop_send_onertt, then record the sealed packet in l->ackst.sent
 * (RFC 9002 A.5 OnPacketSent) at l->now_ms: in flight when it is
 * ack-eliciting or carries PADDING (RFC 9002 2), sized by the whole sealed
 * packet. A full record leaves the packet unrecorded.
 * @return wired_srvloop_send_onertt's result. */
int srvloop_send_onertt_rec(
    wired_srvloop*               l,
    wired_server*                s,
    const wired_srvloop_send_in* in,
    wired_obuf*                  out);

/** RFC 9000 13.2.3: the peer acknowledged [lo, hi]; every remembered
 * ACK-carrying packet in it raises l->ackst.floor1 past that ACK's Largest
 * Acknowledged. */
void srvloop_ackd_on_acked(wired_srvloop* l, u64 lo, u64 hi);

/** RFC 9000 19.3 / RFC 9002 A.7: the packet numbers below 32 that the ACK
 * frames of the opened payload pl acknowledge, as a bitmask (bit i = pn i).
 * Used for the Initial and Handshake spaces, whose boot flight numbers are
 * small (srvboot). */
u32 srvloop_acked_bits(wired_span pl);

/** Test-only: force the packet-number-skip RNG (RFC 9000 21.4) to fail,
 * so no number is ever skipped. The test harness entries set 1 at startup
 * to keep unit runs deterministic; skip tests set 0 for their own scope
 * and restore 1. Production never calls this. */
void srvloop_test_force_pn_skip_rng_fail(int v);

#endif
