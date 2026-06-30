#ifndef QUIC_DGDELIVER_DG_LOSS_H
#define QUIC_DGDELIVER_DG_LOSS_H

#include "common/platform/sys/syscall.h"

/* RFC 9221 5.2: DATAGRAM frames are ack-eliciting but never retransmitted.
 * On loss the application is notified that the datagram was lost; nothing is
 * resent. Returns 1 when a lost DATAGRAM frame should be reported to the app.
 */
int quic_dgdeliver_on_loss(int is_datagram_frame);

/* RFC 9221 5.2: DATAGRAM frames are never retransmitted. Always 0. */
int quic_dgdeliver_retransmit_never(void);

#endif
