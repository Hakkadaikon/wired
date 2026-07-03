#ifndef QUIC_TPVERIFY_CTCID_H
#define QUIC_TPVERIFY_CTCID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 7.3: connection-ID transport parameters are matched in constant
 * time so a mismatch reveals nothing through timing. Variable-length CIDs
 * (0..20 bytes), so quic_ct_diff16/32 do not apply. Length mismatch folds
 * into the accumulator without an early return. Returns 1 if equal. */
static inline int quic_tpverify_cid_eq(quic_span a, quic_span b) {
  usz n = a.n < b.n ? a.n : b.n;
  u8  d = (u8)(a.n ^ b.n);
  for (usz i = 0; i < n; i++) d |= (u8)(a.p[i] ^ b.p[i]);
  return d == 0;
}

#endif
