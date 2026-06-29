#ifndef QUIC_P256SIGN_RFC6979_H
#define QUIC_P256SIGN_RFC6979_H

#include "sys/syscall.h"

/* RFC 6979 Section 3.2 deterministic nonce for P-256 with HMAC-SHA-256.
 * priv and hash are big-endian 32-byte. Writes k (big-endian, 1 <= k < n)
 * to out. For P-256 qlen == 256 == 8*hlen, so bits2int is identity and one
 * HMAC block fills T; the generic shifting/concatenation collapse away. */
void quic_p256sign_k(const u8 priv[32], const u8 hash[32], u8 out[32]);

#endif
