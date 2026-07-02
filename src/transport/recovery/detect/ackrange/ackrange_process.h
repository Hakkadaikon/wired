#ifndef QUIC_ACKRANGE_ACKRANGE_PROCESS_H
#define QUIC_ACKRANGE_ACKRANGE_PROCESS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9002 6 / RFC 9000 19.3: decode a received ACK frame and acknowledge
 * the in-flight packets whose pn falls in any acknowledged range. The pns of
 * newly acked packets are written to newly_acked.out and *newly_acked.n is
 * set to the count. Returns 1 on success, 0 if the frame is malformed. */
int quic_ackrange_process(
    quic_sentpkt *t, quic_span ack_frame, quic_u64out newly_acked);

#endif
