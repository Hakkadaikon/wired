#ifndef QUIC_SENTPKT_LOSS_DETECT_H
#define QUIC_SENTPKT_LOSS_DETECT_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9002 6.1: packet- and time-threshold loss detection. */
#define QUIC_SENTPKT_PACKET_THRESHOLD 3 /* kPacketThreshold */

/* Mark in-flight packets as lost when they are kPacketThreshold or more
 * below largest_acked, or older than now - loss_delay. Lost pns are
 * appended to lost_pns and *n_lost is set to the count. */
void quic_loss_detect(
    quic_sentpkt *t,
    u64           largest_acked,
    u64           now,
    u64           loss_delay,
    u64          *lost_pns,
    usz          *n_lost);

#endif
