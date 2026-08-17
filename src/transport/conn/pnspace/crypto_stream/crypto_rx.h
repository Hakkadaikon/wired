#ifndef QUIC_CRYPTO_STREAM_RX_H
#define QUIC_CRYPTO_STREAM_RX_H

#include "transport/stream/flow/flow/reassemble.h"

/* RFC 9000 19.6 / 7.5: reassemble CRYPTO frame data arriving out of order or
 * overlapping into the contiguous TLS byte stream, delivering only the prefix
 * from offset 0. */

/** RFC 9000 19.6 / 7.5: reassembly state for one CRYPTO stream, tracking how
 * much of the contiguous prefix has already been read out. */
typedef struct {
  reasm reasm;
  u64   read_upto; /* bytes already handed out via read */
} crypto_rx;

void crypto_stream_rx_init(crypto_rx* r);

/* Feed a received CRYPTO frame payload at offset. Returns 1 on success, 0 if
 * it exceeds the reassembly buffer. Overlapping/duplicate data is idempotent.
 */
int crypto_stream_recv(crypto_rx* r, u64 offset, wired_span data);

/* Same as crypto_stream_recv, but on failure also writes the transport
 * error code (RFC 9000 7.5: CRYPTO_BUFFER_EXCEEDED) to *error_code so the
 * caller can close the connection with it. Returns 1 on success, 0 on
 * failure (*error_code set only in that case). */
int crypto_stream_recv_ec(
    crypto_rx* r, u64 offset, wired_span data, u64* error_code);

/* Copy the newly contiguous prefix (past what was already read) into out,
 * writing its length to out->len. Returns 1, or 0 if out->cap is too small
 * for the available bytes. */
int crypto_stream_read(crypto_rx* r, wired_obuf* out);

#endif
