#ifndef QUIC_CRYPTO_STREAM_TX_H
#define QUIC_CRYPTO_STREAM_TX_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.6: carry TLS handshake bytes in CRYPTO frames (type 0x06).
 * Bytes longer than max_frame are split across consecutive CRYPTO frames at
 * increasing offsets starting from base_offset. */

/* Emit CRYPTO frame(s) for tls_bytes[0..len) into out (cap bytes), each frame
 * payload at most max_frame bytes. Writes the total encoded length to *out_len.
 * Returns 1 on success, 0 if max_frame is 0 or out is too small. */
int quic_crypto_stream_emit(const u8 *tls_bytes, usz len, u64 base_offset,
                            usz max_frame, u8 *out, usz cap, usz *out_len);

#endif
