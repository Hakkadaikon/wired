#ifndef QUIC_CRECV_COLLECT_H
#define QUIC_CRECV_COLLECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.6 / 7.5: reassemble CRYPTO frames received in a Handshake (or
 * Initial) packet payload into a single in-order byte stream of TLS handshake
 * messages. Out-of-order and split frames are placed at their offset; only the
 * contiguous prefix from offset 0 is exposed to TLS. Fixed buffer, no alloc. */

#define QUIC_CRECV_BUF 2048

typedef struct {
    u8 buf[QUIC_CRECV_BUF];
    u8 filled[QUIC_CRECV_BUF]; /* 1 where a byte has been written */
    usz received_to;           /* contiguous bytes available from offset 0 */
} quic_crecv;

void quic_crecv_init(quic_crecv *s);

/* Walk a payload, write every CRYPTO frame at its offset, ignore other frames.
 * Updates the contiguous prefix. Returns 1, or 0 if a CRYPTO frame falls
 * outside the buffer (RFC 9000 19.6). */
int quic_crecv_collect(quic_crecv *s, const u8 *frames, usz len);

#endif
