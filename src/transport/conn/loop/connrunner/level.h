#ifndef CONNRUNNER_LEVEL_H
#define CONNRUNNER_LEVEL_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2 / RFC 9001 4: map a raw packet's first byte to the protection
 * level it is processed at. Long-header Initial/Handshake map to the matching
 * keyset level; a short header is always 1-RTT. */

/* Write the LEVEL_* for byte0, whose long-header type bits are read under
 * the connection's `version` (RFC 9369 3.2; 0 means v1), into *level.
 * Returns 1 on a level this loop handles (Initial, Handshake, 1-RTT), 0 for
 * 0-RTT, Retry, or a non-packet. */
int connrunner_packet_level(u8 byte0, u32 version, int* level);

#endif
