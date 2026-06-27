#ifndef QUIC_UTIL_CT_H
#define QUIC_UTIL_CT_H

#include "sys/syscall.h"

/* Constant-time 16-byte compare used by AEAD tag verification.
 * Returns 0 if equal, nonzero otherwise. Inline so both AEADs share it
 * without a separate translation unit. */
static inline u8 quic_ct_diff16(const u8 a[16], const u8 b[16])
{
    u8 d = 0;
    for (usz i = 0; i < 16; i++) d |= a[i] ^ b[i];
    return d;
}

/* Constant-time 32-byte compare (e.g. HMAC-SHA256 tokens). 0 if equal. */
static inline u8 quic_ct_diff32(const u8 a[32], const u8 b[32])
{
    u8 d = 0;
    for (usz i = 0; i < 32; i++) d |= a[i] ^ b[i];
    return d;
}

#endif
