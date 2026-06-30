#ifndef QUIC_PACKET_PTYPE_H
#define QUIC_PACKET_PTYPE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2: a long header's logical packet type, from bits 5-4 of
 * byte 0. QUIC_PT_NONE marks a byte that is not a (valid-form) long header. */

#define QUIC_PT_NONE      (-1)
#define QUIC_PT_INITIAL   0
#define QUIC_PT_0RTT      1
#define QUIC_PT_HANDSHAKE 2
#define QUIC_PT_RETRY     3

/* True if byte0 has the long-header form bit (RFC 9000 17.2). */
int quic_packet_is_long(u8 byte0);

/* Logical long-header type for byte0, or QUIC_PT_NONE if it is not a long
 * header. Does not check the fixed bit (RFC 9000 17.2 type bits only). */
int quic_packet_long_type(u8 byte0);

#endif
