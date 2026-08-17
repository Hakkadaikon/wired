#ifndef PACKET_PTYPE_H
#define PACKET_PTYPE_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/version.h"

/* RFC 9000 17.2 (v1) / RFC 9369 3.2 (v2): a long header's logical packet
 * type, from bits 5-4 of byte 0. The wire-to-logical mapping is
 * version-dependent (v2's bits are a rotation of v1's); PT_NONE marks a
 * byte that is not a (valid-form) long header, or a version this SDK does
 * not know how to interpret type bits for. */

#define PT_NONE (-1)
#define PT_INITIAL 0
#define PT_0RTT 1
#define PT_HANDSHAKE 2
#define PT_RETRY 3

/* True if byte0 has the long-header form bit (RFC 9000 17.2). */
int packet_is_long(u8 byte0);

/* Logical long-header type for byte0 under `version`, or PT_NONE if it
 * is not a long header or version is neither VERSION_1 nor
 * VERSION_2. Does not check the fixed bit. */
int packet_long_type(u8 byte0, u32 version);

#endif
