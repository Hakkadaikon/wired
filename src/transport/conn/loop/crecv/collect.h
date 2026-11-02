#ifndef CRECV_COLLECT_H
#define CRECV_COLLECT_H

#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9000 19.6 / 7.5: reassemble CRYPTO frames received in a Handshake (or
 * Initial) packet payload into a single in-order byte stream of TLS handshake
 * messages. Out-of-order and split frames are placed at their offset; only the
 * contiguous prefix from offset 0 is exposed to TLS. Fixed buffer, no alloc. */

/** Handshake-level reassembly capacity in bytes. RFC 9000 7.5: an
 * implementation "MUST support buffering at least 4096 bytes" of
 * out-of-order CRYPTO data; the buffer spans offset 0..cap of one level's
 * stream and is never expanded (data past it closes with
 * CRYPTO_BUFFER_EXCEEDED). Sized for the largest client Handshake stream of
 * client authentication (RFC 8446 4.4.2): 4 certificates of ~2 KB RSA
 * (8,192 + 4 x 5 entry framing + 8 header), an RSA-4096 CertificateVerify
 * (520) and a SHA-384 Finished (52) is 8,792 bytes; 12,288 leaves room for
 * ~2.5 KB certificates. Costs 2 x 12,288 bytes per connection. */
#define CRECV_BUF 12288

/** Initial-level (ClientHello) reassembly capacity in bytes: the RFC 9000
 * 7.5 minimum, past a post-quantum hybrid ClientHello (~1.7 KB). Kept apart
 * from CRECV_BUF so client auth neither raises the ClientHello limit nor the
 * boot accumulator's 2 x 4,096 bytes. */
#define CRECV_INITIAL_BUF 4096

/** CRYPTO stream reassembly counters. The backing memory (2 x cap bytes:
 * cap stream bytes, then a cap-byte filled map) lives in the owner and is
 * passed to every crecv_* call, so copying the owner by value stays safe. */
typedef struct {
  usz cap;         /**< stream bytes the backing memory holds */
  usz received_to; /**< contiguous bytes available from offset 0 */
  /** RFC 9000 7.5: 1 once a CRYPTO frame reached past cap -- the buffer is
   * never expanded, so the owner closes with CRYPTO_BUFFER_EXCEEDED. */
  int overflow;
} crecv;

/** Start with an empty reassembly buffer.
 * @param s reassembly state to initialize
 * @param mem backing memory of 2 x cap bytes, owned by s's owner
 * @param cap capacity: CRECV_INITIAL_BUF or CRECV_BUF */
void crecv_init(crecv* s, u8* mem, usz cap);

/** Walk a payload, write every CRYPTO frame at its offset, ignore other
 * frames. Updates the contiguous prefix.
 * @param s reassembly state
 * @param mem the backing memory given to crecv_init
 * @param frames the packet payload to walk
 * @param len length of frames in bytes
 * @return 1, or 0 if a CRYPTO frame falls outside the buffer
 * (RFC 9000 19.6). */
int crecv_collect(crecv* s, u8* mem, const u8* frames, usz len);

#endif
