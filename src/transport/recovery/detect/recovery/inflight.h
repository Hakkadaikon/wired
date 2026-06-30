#ifndef QUIC_RECOVERY_INFLIGHT_H
#define QUIC_RECOVERY_INFLIGHT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 2/A.5: ack-eliciting, in-flight, and byte-counting classification.
 */

/* Ack-eliciting iff it carries any frame other than
 * PADDING/ACK/CONNECTION_CLOSE. */
int quic_pkt_ack_eliciting(int has_non_ack_frame);

/* In-flight iff ack-eliciting or carrying PADDING (consumes congestion bytes).
 */
int quic_pkt_in_flight(int ack_eliciting, int has_padding);

/* Bytes counted toward congestion control: size when in-flight, else 0. */
u64 quic_pkt_counts_bytes(int in_flight, u64 size);

#endif
