#ifndef QUIC_PACKET_COALORDER_H
#define QUIC_PACKET_COALORDER_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.2: a short-header packet carries no Length field, so when
 * packets are coalesced into one datagram a short header can only be the
 * last packet. Long headers (which have a Length) may sit anywhere.
 *
 * Given a packet's first byte and whether it is the last packet in the
 * datagram, returns 1 if its placement is allowed, 0 otherwise. */
int quic_coalesce_short_must_be_last(u8 byte0, int is_last);

#endif
