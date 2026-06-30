#ifndef QUIC_PACKET_INITTOKEN_H
#define QUIC_PACKET_INITTOKEN_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2.2: an Initial packet carries a Token Length (varint) followed
 * by that many Token bytes. An empty token (length 0) is valid. This codec
 * handles only the Token Length + Token fields. */

/* Write Token Length(varint) + token (len bytes) into buf (cap total).
 * Returns bytes written, or 0 if it does not fit. len 0 writes just a 0. */
usz quic_inittoken_put(u8 *buf, usz cap, const u8 *token, usz len);

/* Parse Token Length + Token at buf (n readable). On success sets *token
 * (into buf, NULL if len 0) and *len, and returns bytes consumed; 0 if the
 * length varint or the token bytes overrun n. */
usz quic_inittoken_get(const u8 *buf, usz n, const u8 **token, usz *len);

#endif
