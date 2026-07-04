#ifndef QUIC_LOSSDRIVE_LOSSDRIVE_H
#define QUIC_LOSSDRIVE_LOSSDRIVE_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* Inputs to one loss-detection pass. Times are in us. */
typedef struct {
  u64 largest_acked;
  u64 now;
  u64 loss_delay;
} quic_lossdrive_in;

/* RFC 9002 6: drive loss detection after an ACK (or on PTO). Runs the
 * packet/time threshold scan, removes packets judged lost from the
 * sent-packet table, and returns their pns as retransmission candidates in
 * lost.out; *lost.n is set to the count. */
void quic_lossdrive_on_ack(
    quic_sentpkt* state, const quic_lossdrive_in* in, quic_u64out lost);

#endif
