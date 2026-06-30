#ifndef QUIC_SENTMETA_DETECT_LOSS_H
#define QUIC_SENTMETA_DETECT_LOSS_H

#include "transport/recovery/rtx/sentmeta/record.h"

/* RFC 9002 6.1: packet threshold (kPacketThreshold). */
#define QUIC_SENTMETA_PACKET_THRESHOLD 3

/* RFC 9002 6.1: declare lost any tracked packet at or below largest_acked by
 * kPacketThreshold (6.1.1) or sent before now - loss_delay (6.1.2). Lost PNs
 * are written to lost_pns / n_lost and removed from the ring, dropping their
 * bytes from total_in_flight (7.4). lost_pns must hold QUIC_SENTMETA_CAP. */
void quic_sentmeta_detect_loss(
    quic_sentmeta *m,
    u64            largest_acked,
    u64            now,
    u64            loss_delay,
    u64           *lost_pns,
    usz           *n_lost);

#endif
