#ifndef QUIC_BIGNUM_MODEXP_H
#define QUIC_BIGNUM_MODEXP_H

#include "crypto/asymmetric/bignum/bignum.h"

/* out = base^exp mod mod, for 2048-bit operands. base must be < mod.
 * Bitwise square-and-multiply with a division-free modular multiply
 * (double-and-add). Correctness first; verification is rare. */
void quic_bn_modexp(
    quic_bn *out, const quic_bn *base, const quic_bn *exp, const quic_bn *mod);

#endif
