#ifndef ECDSASIG_SIG_VALUE_H
#define ECDSASIG_SIG_VALUE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* SEC1 C.5 ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s }. DER-encodes the
 * two 32-octet big-endian scalars into out (cap octets) and sets *out_len (the
 * whole SEQUENCE, typically 70-72 octets). Returns 1 ok, 0 if it would not fit.
 */
int ecdsasig_encode(
    const u8 r[32], const u8 s[32], u8* out, usz cap, usz* out_len);

/* Strict-DER decode of an ECDSA-Sig-Value occupying all of sig into n-octet
 * big-endian r and s (n = 32 for P-256, 48 for P-384). Rejects trailing data
 * after the SEQUENCE, extra elements inside it, non-minimal length or
 * INTEGER encodings, negative INTEGERs, and values wider than n. Returns 1
 * ok, 0 on any deviation. */
int ecdsasig_decode(wired_span sig, u8* r, u8* s, usz n);

#endif
