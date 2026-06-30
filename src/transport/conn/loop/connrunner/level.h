#ifndef QUIC_CONNRUNNER_LEVEL_H
#define QUIC_CONNRUNNER_LEVEL_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2 / RFC 9001 4: map a raw packet's first byte to the protection
 * level it is processed at. Long-header Initial/Handshake map to the matching
 * keyset level; a short header is always 1-RTT. */

/* Write the QUIC_LEVEL_* for byte0 into *level. Returns 1 on a level this loop
 * handles (Initial, Handshake, 1-RTT), 0 for 0-RTT, Retry, or a non-packet. */
int quic_connrunner_packet_level(u8 byte0, int *level);

#endif
