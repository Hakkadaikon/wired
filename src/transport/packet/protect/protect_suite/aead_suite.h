#ifndef QUIC_PROTECT_SUITE_AEAD_SUITE_H
#define QUIC_PROTECT_SUITE_AEAD_SUITE_H

#include "common/bytes/span/span.h"

/* RFC 9001 5.3: per-suite AEAD seal/open for QUIC packet protection. The
 * 12-byte nonce is iv XOR pn (left-padded). AES suites (0x1301) use
 * AES-128-GCM, ChaCha suites (0x1303) use ChaCha20-Poly1305. key is 16
 * bytes for AES, 32 for ChaCha; iv is 12 bytes either way. */

/* Protection inputs shared by seal and open: the cipher suite, AEAD key/iv,
 * the packet number (for the nonce), and the header bytes used as AAD.
 * Build one on the stack per packet and pass it by pointer. */
typedef struct {
  u16       suite;
  const u8* key;
  const u8* iv;
  u64       pn;
  quic_span aad;
} quic_aead_suite_op;

/* Seal pt into out as ciphertext followed by the 16-byte tag. Returns the
 * total written length (pt.n + 16), or 0 on an unknown suite. */
usz quic_aead_suite_seal(const quic_aead_suite_op* op, quic_span pt, u8* out);

/* Open ct (ct.n ciphertext bytes followed by a 16-byte tag) into pt.
 * Returns ct.n on success, 0 on tag mismatch or unknown suite. */
usz quic_aead_suite_open(const quic_aead_suite_op* op, quic_span ct, u8* pt);

#endif
