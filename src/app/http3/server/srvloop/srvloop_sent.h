#ifndef WIRED_SRVLOOP_SRVLOOP_SENT_H
#define WIRED_SRVLOOP_SRVLOOP_SENT_H

#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvloop/srvloop_wt.h"

/** wired_srvloop_send_onertt, then record the sealed packet in l->sent
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
 * ACK-carrying packet in it raises l->ack_floor1 past that ACK's Largest
 * Acknowledged. */
void srvloop_ackd_on_acked(wired_srvloop* l, u64 lo, u64 hi);

#endif
