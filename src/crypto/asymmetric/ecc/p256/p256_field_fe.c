#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

void p256_fp_mul(p256_fe r, fpab ab, const p256_fe m) {
  u64 w[8];
  p256_fe_mul_wide(w, ab.a, ab.b);
  p256_fe_reduce_wide(r, w, m);
}

void p256_fp_sqr(p256_fe r, const p256_fe a, const p256_fe m) {
  p256_fp_mul(r, (fpab){a, a}, m);
}

/* FIPS 186-4 D.2.5 fast reduction modulo the P-256 prime p = 2^256 - 2^224 +
 * 2^192 + 2^96 - 1. The 512-bit product is viewed as sixteen 32-bit words
 * c0..c15 (c0 least significant); p's special form lets the reduction be a few
 * 256-bit add/subtracts of words rearranged from the high half, replacing the
 * generic bit-at-a-time long division (which cost ~885ms per scalar mul). The
 * generic p256_fp_mul stays for the group order n; this path is p only.
 * Correctness is pinned by a differential test against the generic reducer. */
