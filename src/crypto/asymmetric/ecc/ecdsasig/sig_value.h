#ifndef QUIC_ECDSASIG_SIG_VALUE_H
#define QUIC_ECDSASIG_SIG_VALUE_H

#include "common/platform/sys/syscall.h"

/* SEC1 C.5 ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s }. DER-encodes the
 * two 32-octet big-endian scalars into out (cap octets) and sets *out_len (the
 * whole SEQUENCE, typically 70-72 octets). Returns 1 ok, 0 if it would not fit.
 */
int quic_ecdsasig_encode(
    const u8 r[32], const u8 s[32], u8 *out, usz cap, usz *out_len);

#endif
