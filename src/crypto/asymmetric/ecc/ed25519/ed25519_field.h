#ifndef QUIC_ED25519_FIELD_H
#define QUIC_ED25519_FIELD_H

#include "common/platform/sys/syscall.h"

/* Internal interface between the Ed25519 field/group arithmetic
 * (ed25519_field.c) and the signing/verification logic (ed25519_sign.c).
 * Field GF(2^255-19) as five 51-bit limbs; group points in extended
 * homogeneous coordinates (RFC 8032 5.1). Not a public API. */

typedef u64 quic_ed_fe[5];

/* Extended homogeneous coordinates (X, Y, Z, T) (RFC 8032 5.1.4). */
typedef struct { quic_ed_fe X, Y, Z, T; } quic_ed_ge;

/* Base point B (RFC 8032 5.1) as an extended-coordinate point. */
void quic_ed_ge_base(quic_ed_ge *p);

/* p3 = p1 + p2 on the twisted Edwards curve (RFC 8032 5.1.4). */
void quic_ed_ge_add(quic_ed_ge *p3, const quic_ed_ge *p1, const quic_ed_ge *p2);

/* q = [scalar]p for a 256-bit little-endian scalar. Verification only;
 * constant time is not required. */
void quic_ed_ge_scalarmult(quic_ed_ge *q, const u8 scalar[32],
                           const quic_ed_ge *p);

/* Encode an extended point to 32 bytes (RFC 8032 5.1.2). */
void quic_ed_ge_encode(u8 out[32], const quic_ed_ge *p);

/* Decode a 32-byte point into extended coordinates (RFC 8032 5.1.3).
 * Returns 1 on success, 0 if the point is not on the curve. */
int quic_ed_ge_decode(quic_ed_ge *p, const u8 in[32]);

#endif
