#ifndef P256SIGN_RFC6979_H
#define P256SIGN_RFC6979_H

#include "common/platform/sys/syscall.h"

/* RFC 6979 Section 3.2 deterministic nonce for P-256 with HMAC-SHA-256.
 * priv and hash are big-endian 32-byte. Writes k (big-endian, 1 <= k < n)
 * to out. For P-256 qlen == 256 == 8*hlen, so bits2int is identity and one
 * HMAC block fills T; the generic shifting/concatenation collapse away. */
void p256sign_k(const u8 priv[32], const u8 hash[32], u8 out[32]);

/* 1 if candidate k is acceptable to the caller (e.g. yields r != 0). */
typedef int (*p256sign_k_ok)(const u8 cand[32], void* ctx);

/* RFC 6979 Section 3.2 step h / Section 3.4: like p256sign_k, but a
 * candidate is accepted only when it is both in range (1 <= k < n) and
 * "suitable" per ok(); otherwise the K/V state is advanced (step h.3's
 * K = HMAC_K(V||0x00); V = HMAC_K(V)) and a new candidate is drawn. Used to
 * retry when a suitable k must additionally yield r != 0 (and, for ECDSA,
 * s != 0). */
void p256sign_k_retry(
    const u8      priv[32],
    const u8      hash[32],
    u8            out[32],
    p256sign_k_ok ok,
    void*         ctx);

#endif
