#ifndef QUIC_BIGNUM_MODEXP_H
#define QUIC_BIGNUM_MODEXP_H

#include "crypto/asymmetric/bignum/bignum.h"

/** Exponent and modulus of a modular exponentiation. */
typedef struct {
  const bn* exp;
  const bn* mod;
} bn_expmod;

/* out = base^exp mod mod, for 2048-bit operands. base must be < mod.
 * Bitwise square-and-multiply with a division-free modular multiply
 * (double-and-add). Correctness first; verification is rare. */
void bn_modexp(bn* out, const bn* base, bn_expmod em);

#endif
