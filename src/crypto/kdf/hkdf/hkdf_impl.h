#ifndef CRYPTO_KDF_HKDF_HKDF_IMPL_H
#define CRYPTO_KDF_HKDF_HKDF_IMPL_H

/* Internal to the hkdf*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/kdf/hkdf/hkdf.h"

/* Loop-invariant HKDF-Expand inputs: the PRK and the info bytes. */
typedef struct {
  const u8*  prk;
  wired_span info;
} hkdf_xctx;

/* Loop-invariant HKDF-Expand inputs: the PRK and the info bytes. */
typedef struct {
  const u8*  prk;
  wired_span info;
} hkdf_xctx_384;

#endif
