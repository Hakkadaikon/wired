#ifndef QUIC_CRYPTO_STREAM_TX_H
#define QUIC_CRYPTO_STREAM_TX_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 19.6: carry TLS handshake bytes in CRYPTO frames (type 0x06).
 * Bytes longer than max_frame are split across consecutive CRYPTO frames at
 * increasing offsets starting from base_offset. */

/* Everything quic_crypto_stream_emit needs besides tls_bytes and the output. */
typedef struct {
  u64 base_offset;
  usz max_frame;
} quic_crypto_stream_emit_in;

/* Emit CRYPTO frame(s) for tls_bytes into out, each frame payload at most
 * in->max_frame bytes. Writes the total encoded length to out->len. Returns 1
 * on success, 0 if max_frame is 0 or out is too small. */
int quic_crypto_stream_emit(
    quic_span tls_bytes, const quic_crypto_stream_emit_in* in, quic_obuf* out);

#endif
