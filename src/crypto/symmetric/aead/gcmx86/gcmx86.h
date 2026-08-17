#ifndef QUIC_GCMX86_GCMX86_H
#define QUIC_GCMX86_GCMX86_H

#include "common/bytes/span/span.h"

/* Hardware AES-128-GCM (NIST SP 800-38D) using x86-64 AES-NI and PCLMULQDQ
 * via the arch adapter's instruction wrappers (common/arch/x8664/simd128.h;
 * no intrinsics headers: this tree is libc-free). Same AEAD as
 * crypto/symmetric/aead/gcm (RFC 9001 5.3), roughly two orders of
 * magnitude faster per block. Callers must gate on quic_gcmx86_supported()
 * and fall back to the scalar quic_gcm_* path when it returns 0. */

#define QUIC_GCMX86_NONCE 12
#define QUIC_GCMX86_TAG 16

/**
 * Expanded AES-128-GCM key: 11 round keys (FIPS 197 byte order, as AESENC
 * consumes them) plus the GHASH subkey H = AES_K(0^128).
 *
 * 16-byte aligned so the compiler may use aligned SSE loads; the accessors
 * copy byte-wise, so no additional caller-side alignment is required beyond
 * placing the struct normally (its own alignment attribute suffices).
 */
typedef struct __attribute__((aligned(16))) {
  u8 rk[11][16]; /**< round keys 0..10, 16 bytes each */
  u8 h[16];      /**< GHASH subkey H = AES_K(0^128) */
} quic_gcmx86;

/* 1 when the CPU has both AES-NI and PCLMULQDQ (CPUID.1:ECX bits 25 and 1),
 * 0 otherwise. Result is cached after the first call. */
int quic_gcmx86_supported(void);

/* Expand key into the round-key schedule and precompute H. Call only when
 * quic_gcmx86_supported() returned 1. */
void quic_gcmx86_init(quic_gcmx86* x, const u8 key[16]);

/* Seal: out receives ciphertext || 16-byte tag. Returns pt.n + 16. */
usz quic_gcmx86_seal(
    const quic_gcmx86* x,
    const u8           nonce[QUIC_GCMX86_NONCE],
    wired_span         aad,
    wired_span         pt,
    u8*                out);

/* Open: ct spans ciphertext || 16-byte tag. On tag mismatch returns 0 and
 * writes nothing. On success writes ct.n - 16 plaintext bytes to out and
 * returns that length (an authentic empty plaintext also returns 0). */
usz quic_gcmx86_open(
    const quic_gcmx86* x,
    const u8           nonce[QUIC_GCMX86_NONCE],
    wired_span         aad,
    wired_span         ct,
    u8*                out);

#endif
