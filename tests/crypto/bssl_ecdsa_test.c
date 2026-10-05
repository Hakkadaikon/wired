#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"
#include "test.h"
#include "vectors/boringssl/bssl_vec.h"
#include "vectors/boringssl/ecdsa_verify_tests.h"

/* BoringSSL crypto/fipsmodule/ecdsa/ecdsa_verify_tests.txt @
 * dd73e69a4e86fa178a4d19033c691e9b42cc1088. Expected result is the file's
 * (Invalid present = must fail); wired is never consulted for it. */

#define BSL_EC_MAX 80 /* longest Digest in the file is 71 bytes */

typedef struct {
  const char* curve;
  usz         size; /* field / group order bytes */
  int (*verify)(const u8*, const u8*, const u8*, const u8*, const u8*);
  u32 added, pass, fail, skip;
} bsl_ec_curve;

/* Big-endian integer src[0..n) as a size-byte value (FIPS 186-4 6.4.2:
 * short digests are zero-extended on the left, longer ones keep their
 * leftmost bits; for a byte-aligned order that is the leftmost bytes).
 * keep_lead: a value longer than size is unrepresentable -> return 0. */
static int bsl_ec_fit(u8* dst, usz size, const u8* src, usz n, int digest) {
  usz skip = n > size ? (digest ? 0 : n - size) : 0;
  usz take = n > size && digest ? size : n - skip;
  for (usz i = 0; i < size; i++) dst[i] = 0;
  for (usz i = 0; i < take; i++) dst[size - take + i] = src[i];
  for (usz i = 0; i < skip; i++)
    if (src[i]) return 0;
  return 1;
}

static int bsl_ec_run(const bsl_ec_curve* k, const bssl_case* c) {
  u8          raw[5][BSL_EC_MAX], f[5][BSL_EC_MAX];
  const char* names[5] = {"X", "Y", "R", "S", "Digest"};
  int         ok       = 1;
  for (int i = 0; i < 5; i++) {
    ssz n = bssl_bytes(
        bssl_get(bssl_ecdsa_verify_tests_attrs, c, names[i]), raw[i],
        BSL_EC_MAX);
    if (n < 0) return -1;
    /* an over-long value can never be a valid field element: reject */
    ok &= bsl_ec_fit(f[i], k->size, raw[i], (usz)n, i == 4);
  }
  if (!ok) return 0;
  return k->verify(f[0], f[1], f[2], f[3], f[4]);
}

static void bsl_ec_case(bsl_ec_curve* k, const bssl_case* c) {
  int want = !bssl_get(bssl_ecdsa_verify_tests_attrs, c, "Invalid");
  int got  = bsl_ec_run(k, c);
  k->added++;
  if (got == want) {
    k->pass++;
    return;
  }
  k->fail++;
  printf(
      "FAIL ecdsa_verify_tests.txt:%u-%u %s want %s got %d\n", c->line_first,
      c->line_last, k->curve, want ? "valid" : "invalid", got);
  CHECK(got == want);
}

static int bsl_ec_isolated(const char* curve) {
  return !bssl_streq(curve, "P-256") && !bssl_streq(curve, "P-384");
}

void test_bssl_ecdsa(void) {
  bsl_ec_curve k256 = {"P-256", 32, ecdsa_p256_verify, 0, 0, 0, 0};
  bsl_ec_curve k384 = {"P-384", 48, ecdsa_p384_verify, 0, 0, 0, 0};
  u32          skip = 0;
  for (u32 i = 0; i < sizeof bssl_ecdsa_verify_tests_cases /
                          sizeof bssl_ecdsa_verify_tests_cases[0];
       i++) {
    const bssl_case* c  = &bssl_ecdsa_verify_tests_cases[i];
    const char*      cv = bssl_get(bssl_ecdsa_verify_tests_attrs, c, "Curve");
    if (bsl_ec_isolated(cv))
      skip++; /* curve not implemented: P-224, P-521, secp224k1 */
    else
      bsl_ec_case(bssl_streq(cv, "P-256") ? &k256 : &k384, c);
  }
  printf(
      "bssl ecdsa-P-256: added %u pass %u fail %u skip 0\n", k256.added,
      k256.pass, k256.fail);
  printf(
      "bssl ecdsa-P-384: added %u pass %u fail %u skip 0\n", k384.added,
      k384.pass, k384.fail);
  printf(
      "bssl ecdsa-other: added %u pass 0 fail 0 skip %u (curve not "
      "implemented)\n",
      skip, skip);
}
