#ifndef TLS_HANDSHAKE_CORE_TLS_X25519_IMPL_H
#define TLS_HANDSHAKE_CORE_TLS_X25519_IMPL_H

/* Internal to the x25519*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "tls/handshake/core/tls/x25519.h"

/* GF(2^255-19) as five 51-bit limbs. Implementation follows the standard
 * radix-2^51 representation (ref10-style), kept in small helpers for CCN<=3. */

typedef u64 fe[5];

#define MASK51 0x7ffffffffffffULL

/* The Montgomery x25519_ladder's running (x2,z2,x3,z3) state, mutated in place
 * each step. */
typedef struct {
  u64 x2[5], z2[5], x3[5], z3[5];
} ladder_state;

void x25519_fe_0(fe h);
void x25519_fe_1(fe h);
void x25519_fe_copy(fe h, const fe f);
void x25519_fe_add(fe h, const fe f, const fe g);
void x25519_fe_sub(fe h, const fe f, const fe g);
void x25519_fe_mul(fe h, const fe f, const fe g);
void x25519_fe_sq(fe h, const fe f);
void x25519_fe_mul121666(fe h, const fe f);
void x25519_fe_cswap(fe f, fe g, u64 swap);
void x25519_fe_invert(fe out, const fe z);
void x25519_fe_frombytes(fe h, const u8* s);
void x25519_fe_tobytes(u8* s, const fe h);
void x25519_ladder_step(ladder_state* st, const fe x1);
void x25519_ladder(fe x2, fe z2, const u8 e[32], const fe x1);

#endif
