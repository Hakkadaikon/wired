#ifndef QUIC_PACKET_INITTOKEN_H
#define QUIC_PACKET_INITTOKEN_H

#include "common/bytes/span/span.h"

/* RFC 9000 17.2.2: an Initial packet carries a Token Length (varint) followed
 * by that many Token bytes. An empty token (length 0) is valid. This codec
 * handles only the Token Length + Token fields. */

/* Write Token Length(varint) + token bytes into buf (cap total).
 * Returns bytes written, or 0 if it does not fit. An empty token writes
 * just a 0. */
usz quic_inittoken_put(u8* buf, usz cap, quic_span token);

/* Parse Token Length + Token at buf (n readable). On success sets *token
 * (a view into buf, p NULL if empty) and returns bytes consumed; 0 if the
 * length varint or the token bytes overrun n. */
usz quic_inittoken_get(const u8* buf, usz n, quic_span* token);

#endif
