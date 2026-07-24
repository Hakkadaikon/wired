#ifndef QUIC_KEYUPDATE_AEADINTEGRITY_H
#define QUIC_KEYUPDATE_AEADINTEGRITY_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.6 AEAD integrity limit. Unlike the confidentiality limit
 * (aeadlimit.h), which bounds packets encrypted, the integrity limit bounds
 * the number of received packets that FAIL authentication under one set of
 * keys. For AEAD_AES_128_GCM and AEAD_AES_256_GCM the limit is 2^52; for
 * AEAD_CHACHA20_POLY1305 it is 2^36 (RFC 9001 Table 3). Once the limit is
 * reached, the connection MUST be closed with AEAD_LIMIT_REACHED (0x0f). */

#define QUIC_AEAD_INTEGRITY_LIMIT_AESGCM (1ULL << 52)
#define QUIC_AEAD_INTEGRITY_LIMIT_CHACHA (1ULL << 36)

/* Returns 1 if auth_failures (packets that failed AEAD authentication under
 * one key) has reached the AEAD's integrity limit, 0 otherwise. is_chacha
 * selects the ChaCha20-Poly1305 limit, else AES-GCM (128 or 256 share the
 * same limit). */
int quic_aead_integrity_exceeded(u64 auth_failures, int is_chacha);

#endif
