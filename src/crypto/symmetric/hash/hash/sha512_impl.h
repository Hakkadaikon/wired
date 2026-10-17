#ifndef CRYPTO_SYMMETRIC_HASH_HASH_SHA512_IMPL_H
#define CRYPTO_SYMMETRIC_HASH_HASH_SHA512_IMPL_H

/* Internal to the sha512*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/symmetric/hash/hash/sha512.h"

#define S512ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S512BS0(x) (S512ROR(x, 28) ^ S512ROR(x, 34) ^ S512ROR(x, 39))
#define S512BS1(x) (S512ROR(x, 14) ^ S512ROR(x, 18) ^ S512ROR(x, 41))
#define S512SS0(x) (S512ROR(x, 1) ^ S512ROR(x, 8) ^ ((x) >> 7))
#define S512SS1(x) (S512ROR(x, 19) ^ S512ROR(x, 61) ^ ((x) >> 6))

#endif
