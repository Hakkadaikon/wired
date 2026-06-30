#ifndef QUIC_CRYPTO_STREAM_RX_H
#define QUIC_CRYPTO_STREAM_RX_H

#include "common/platform/sys/syscall.h"
#include "flow/reassemble.h"

/* RFC 9000 19.6 / 7.5: reassemble CRYPTO frame data arriving out of order or
 * overlapping into the contiguous TLS byte stream, delivering only the prefix
 * from offset 0. */

typedef struct {
    quic_reasm reasm;
    u64 read_upto; /* bytes already handed out via read */
} quic_crypto_rx;

void quic_crypto_stream_rx_init(quic_crypto_rx *r);

/* Feed a received CRYPTO frame payload at offset. Returns 1 on success, 0 if
 * it exceeds the reassembly buffer. Overlapping/duplicate data is idempotent. */
int quic_crypto_stream_recv(quic_crypto_rx *r, u64 offset,
                            const u8 *data, usz len);

/* Copy the newly contiguous prefix (past what was already read) into out
 * (cap bytes), writing its length to *out_len. Returns 1, or 0 if cap is too
 * small for the available bytes. */
int quic_crypto_stream_read(quic_crypto_rx *r, u8 *out, usz cap, usz *out_len);

#endif
