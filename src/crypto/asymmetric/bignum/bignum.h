#ifndef QUIC_BIGNUM_BIGNUM_H
#define QUIC_BIGNUM_BIGNUM_H

#include "common/platform/sys/syscall.h"

/* Fixed 4096-bit unsigned big integer as 64 little-endian u64 limbs (sized
 * for RSA-4096 moduli). Minimal operations for RSA signature verification
 * (RFC 8017). */

#define QUIC_BN_LIMBS 64

typedef struct {
  u64 v[QUIC_BN_LIMBS];
} quic_bn;

/* Big-endian bytes -> limbs. len must be <= QUIC_BN_LIMBS*8. */
void quic_bn_from_be(quic_bn* out, const u8* be, usz len);

/* Limbs -> big-endian bytes (len octets, left zero-padded/truncated). */
void quic_bn_to_be(const quic_bn* a, u8* be, usz len);

/* -1 if a<b, 0 if a==b, 1 if a>b. */
int quic_bn_cmp(const quic_bn* a, const quic_bn* b);

/* 1 if a==0, else 0. */
int quic_bn_is_zero(const quic_bn* a);

#endif
