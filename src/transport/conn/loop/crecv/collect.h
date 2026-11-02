#ifndef CRECV_COLLECT_H
#define CRECV_COLLECT_H

#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9000 19.6 / 7.5: reassemble CRYPTO frames received in a Handshake (or
 * Initial) packet payload into a single in-order byte stream of TLS handshake
 * messages. Out-of-order and split frames are placed at their offset; only the
 * contiguous prefix from offset 0 is exposed to TLS. Fixed buffer, no alloc. */

/** Reassembly buffer capacity in bytes. RFC 9000 7.5: an implementation
 * "MUST support buffering at least 4096 bytes" of out-of-order CRYPTO data;
 * the buffer spans offset 0..CRECV_BUF of one level's stream and is never
 * expanded (data past it closes with CRYPTO_BUFFER_EXCEEDED). Sized for the
 * largest client Handshake stream of client authentication (RFC 8446 4.4.2):
 * 4 certificates of ~2 KB RSA (8,192 + 4 x 5 entry framing + 8 header),
 * an RSA-4096 CertificateVerify (520) and a SHA-384 Finished (52) is 8,792
 * bytes; 12,288 leaves room for ~2.5 KB certificates. Two buffers per
 * connection (Initial, Handshake) cost 2 x 2 x 12,288 bytes. */
#define CRECV_BUF 12288

/** CRYPTO stream reassembly state. */
typedef struct {
  u8  buf[CRECV_BUF];    /**< reassembled CRYPTO stream bytes */
  u8  filled[CRECV_BUF]; /**< 1 where a byte has been written */
  usz received_to;       /**< contiguous bytes available from offset 0 */
  /** RFC 9000 7.5: 1 once a CRYPTO frame reached past buf -- the buffer is
   * never expanded, so the owner closes with CRYPTO_BUFFER_EXCEEDED. */
  int overflow;
} crecv;

/** Start with an empty reassembly buffer.
 * @param s reassembly state to initialize */
void crecv_init(crecv* s);

/** Walk a payload, write every CRYPTO frame at its offset, ignore other
 * frames. Updates the contiguous prefix.
 * @param s reassembly state
 * @param frames the packet payload to walk
 * @param len length of frames in bytes
 * @return 1, or 0 if a CRYPTO frame falls outside the buffer
 * (RFC 9000 19.6). */
int crecv_collect(crecv* s, const u8* frames, usz len);

#endif
