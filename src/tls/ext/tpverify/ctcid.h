#ifndef QUIC_TPVERIFY_CTCID_H
#define QUIC_TPVERIFY_CTCID_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3: connection-ID transport parameters are matched in constant
 * time so a mismatch reveals nothing through timing. Variable-length CIDs
 * (0..20 bytes), so quic_ct_diff16/32 do not apply. Length mismatch folds
 * into the accumulator without an early return. Returns 1 if equal. */
static inline int quic_tpverify_cid_eq(const u8 *a, u8 alen,
                                       const u8 *b, u8 blen)
{
    u8 d = (u8)(alen ^ blen);
    u8 n = alen < blen ? alen : blen;
    for (u8 i = 0; i < n; i++) d |= (u8)(a[i] ^ b[i]);
    return d == 0;
}

#endif
