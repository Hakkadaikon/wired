#ifndef QUIC_SENTPKT_LOSS_DETECT_H
#define QUIC_SENTPKT_LOSS_DETECT_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9002 6.1: packet- and time-threshold loss detection. */
#define QUIC_SENTPKT_PACKET_THRESHOLD 3 /* kPacketThreshold */

/* Inputs to one loss-detection pass. */
typedef struct {
  u64 largest_acked;
  u64 now;
  u64 loss_delay;
} quic_loss_params;

/* Mark in-flight packets as lost when they are kPacketThreshold or more
 * below largest_acked, or older than now - loss_delay. Lost pns are
 * appended to lost.out and *lost.n is set to the count. */
void quic_loss_detect(
    quic_sentpkt *t, const quic_loss_params *p, quic_u64out lost);

#endif
