#ifndef MOQVI_H
#define MOQVI_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* draft-ietf-moq-transport-19 1.4.1 Variable-Length Integers.
 * Length = number of leading 1 bits of the first byte + 1 (1..9 bytes);
 * the bits after the first 0 and any subsequent bytes hold the value in
 * network byte order. Covers the full 64-bit range. Non-minimal encodings
 * are valid on decode; the encoder always emits the minimal length.
 * Distinct from the QUIC varint (RFC 9000 16). */

/* Minimal encoded length of v: 1..9 bytes (never fails). */
usz moqvi_len(u64 v);

/* Encode v minimally into buf (must hold moqvi_len(v) bytes).
 * Returns bytes written (1..9). */
usz moqvi_encode(u8* buf, u64 v);

/* Decode from buf of n readable bytes into *out.
 * Returns bytes consumed, or 0 if n too small for the encoded length. */
usz moqvi_decode(const u8* buf, usz n, u64* out);

/* Cursor helpers, same shape as varint_take/put. Each decodes/encodes
 * one integer at buf+*off and advances *off on success. */

/* Returns 1 ok, 0 if truncated (*off unchanged). */
int moqvi_take(wired_span buf, usz* off, u64* out);

/* Returns 1 ok, 0 if no room within cap (*off unchanged). */
int moqvi_put(wired_mspan buf, usz* off, u64 v);

#endif
