#ifndef QUIC_DGDELIVER_DG_RECV_H
#define QUIC_DGDELIVER_DG_RECV_H

#include "sys/syscall.h"

/* RFC 9221 5: extract the payload of a received DATAGRAM frame (type 0x30 or
 * 0x31 at frame[0]) for delivery to the application. *payload points into the
 * frame buffer (a view, no copy) and *payload_len is its length. Returns 1 on
 * success, 0 on a malformed frame. */
int quic_dgdeliver_extract(const u8 *frame, usz len, const u8 **payload, usz *payload_len);

#endif
