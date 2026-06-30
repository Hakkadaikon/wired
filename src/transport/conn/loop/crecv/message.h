#ifndef QUIC_CRECV_MESSAGE_H
#define QUIC_CRECV_MESSAGE_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/loop/crecv/collect.h"

/* RFC 9000 7.5: hand TLS only the in-order contiguous prefix of the crypto
 * stream. A TLS handshake message (RFC 8446 4) is a 1-byte msg_type plus a
 * 3-byte big-endian length; complete_message reports whether the leading one
 * is fully buffered. */

/* Point *msg at the contiguous prefix from offset 0 and write its length.
 * Always succeeds (length may be 0). */
void quic_crecv_message(const quic_crecv *s, const u8 **msg, usz *len);

/* Returns 1 if the leading TLS handshake message is completely buffered in the
 * contiguous prefix (4-byte header + declared body), else 0. */
int quic_crecv_complete_message(const quic_crecv *s);

#endif
