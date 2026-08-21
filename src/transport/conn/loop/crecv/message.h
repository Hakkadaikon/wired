#ifndef CRECV_MESSAGE_H
#define CRECV_MESSAGE_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/loop/crecv/collect.h"

/* RFC 9000 7.5: hand TLS only the in-order contiguous prefix of the crypto
 * stream. A TLS handshake message (RFC 8446 4) is a 1-byte msg_type plus a
 * 3-byte big-endian length; complete_message reports whether the leading one
 * is fully buffered. */

/* Point *msg at the contiguous prefix from offset 0 and write its length.
 * Always succeeds (length may be 0). */
void crecv_message(const crecv* s, const u8** msg, usz* len);

/* Same, but from `off`: the contiguous bytes available at and past off
 * (0-length when off is at or past the contiguous prefix). RFC 8446 4.1.4:
 * a post-HelloRetryRequest ClientHello2 continues the crypto stream at the
 * offset right past ClientHello1, so the second message must be addressable
 * on its own. */
void crecv_message_at(const crecv* s, usz off, const u8** msg, usz* len);

/* Returns 1 if the leading TLS handshake message is completely buffered in the
 * contiguous prefix (4-byte header + declared body), else 0. */
int crecv_complete_message(const crecv* s);

/* Same, but for the message starting at `off` (see crecv_message_at). */
int crecv_complete_message_at(const crecv* s, usz off);

#endif
