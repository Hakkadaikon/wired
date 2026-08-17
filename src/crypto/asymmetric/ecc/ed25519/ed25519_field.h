#ifndef ED25519_FIELD_H
#define ED25519_FIELD_H

#include "common/platform/sys/syscall.h"

/* Internal interface between the Ed25519 field/group arithmetic
 * (ed25519_field.c) and the signing/verification logic (ed25519_sign.c).
 * Field GF(2^255-19) as five 51-bit limbs; group points in extended
 * homogeneous coordinates (RFC 8032 5.1). Not a public API. */

/** GF(2^255-19) field element as five 51-bit limbs. */
typedef u64 ed_fe[5];

/** Extended homogeneous coordinates (X, Y, Z, T) (RFC 8032 5.1.4). */
typedef struct {
  ed_fe X, Y, Z, T;
} ed_ge;

/* Base point B (RFC 8032 5.1) as an extended-coordinate point. */
void ed_ge_base(ed_ge* p);

/* p3 = p1 + p2 on the twisted Edwards curve (RFC 8032 5.1.4). */
void ed_ge_add(ed_ge* p3, const ed_ge* p1, const ed_ge* p2);

/* q = [scalar]p for a 256-bit little-endian scalar. Verification only;
 * constant time is not required. */
void ed_ge_scalarmult(ed_ge* q, const u8 scalar[32], const ed_ge* p);

/* Encode an extended point to 32 bytes (RFC 8032 5.1.2). */
void ed_ge_encode(u8 out[32], const ed_ge* p);

/* Decode a 32-byte point into extended coordinates (RFC 8032 5.1.3).
 * Returns 1 on success, 0 if the point is not on the curve. */
int ed_ge_decode(ed_ge* p, const u8 in[32]);

#endif
