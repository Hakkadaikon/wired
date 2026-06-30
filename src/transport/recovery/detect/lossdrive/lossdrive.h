#ifndef QUIC_LOSSDRIVE_LOSSDRIVE_H
#define QUIC_LOSSDRIVE_LOSSDRIVE_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9002 6: drive loss detection after an ACK (or on PTO). Runs the
 * packet/time threshold scan, removes packets judged lost from the
 * sent-packet table, and returns their pns as retransmission candidates.
 * lost_pns is filled and *n_lost set to the count. Times are in us. */
void quic_lossdrive_on_ack(
    quic_sentpkt *state,
    u64           largest_acked,
    u64           now,
    u64           loss_delay,
    u64          *lost_pns,
    usz          *n_lost);

#endif
