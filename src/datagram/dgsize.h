#ifndef QUIC_DATAGRAM_DGSIZE_H
#define QUIC_DATAGRAM_DGSIZE_H

#include "sys/syscall.h"

/* RFC 9221 5: the largest DATAGRAM payload that fits within a peer's
 * max_datagram_frame_size. The frame overhead is the type (1 byte) plus, when
 * with_len is set (type 0x31), the length varint encoding the payload size.
 * Returns the payload upper bound, or 0 when the limit is too small. */
u64 quic_datagram_max_payload(u64 max_frame_size, int with_len);

#endif
