#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p521/ecdsa_verify.h"
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
  /* P-521 instead takes the raw digest and cuts it to 521 bits itself */
  int (*verify_raw)(const u8*, const u8*, const u8*, const u8*, const u8*, usz);
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
  usz         dlen     = 0;
  for (int i = 0; i < 5; i++) {
    ssz n = bssl_bytes(
        bssl_get(bssl_ecdsa_verify_tests_attrs, c, names[i]), raw[i],
        BSL_EC_MAX);
    if (n < 0) return -1;
    /* an over-long value can never be a valid field element: reject */
    ok &= bsl_ec_fit(f[i], k->size, raw[i], (usz)n, i == 4);
    dlen = (usz)n; /* the Digest's, after the last iteration */
  }
  if (!ok) return 0;
  if (k->verify_raw) return k->verify_raw(f[0], f[1], f[2], f[3], raw[4], dlen);
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

/* The curve's runner, or 0 if wired does not implement the curve. */
static bsl_ec_curve* bsl_ec_pick(bsl_ec_curve* const ks[3], const char* cv) {
  for (int i = 0; i < 3; i++)
    if (bssl_streq(cv, ks[i]->curve)) return ks[i];
  return 0;
}

void test_bssl_ecdsa(void) {
  bsl_ec_curve        k256  = {"P-256", 32, ecdsa_p256_verify, 0, 0, 0, 0, 0};
  bsl_ec_curve        k384  = {"P-384", 48, ecdsa_p384_verify, 0, 0, 0, 0, 0};
  bsl_ec_curve        k521  = {"P-521", 66, 0, ecdsa_p521_verify, 0, 0, 0, 0};
  bsl_ec_curve* const ks[3] = {&k256, &k384, &k521};
  u32                 skip  = 0;
  for (u32 i = 0; i < sizeof bssl_ecdsa_verify_tests_cases /
                          sizeof bssl_ecdsa_verify_tests_cases[0];
       i++) {
    const bssl_case* c  = &bssl_ecdsa_verify_tests_cases[i];
    const char*      cv = bssl_get(bssl_ecdsa_verify_tests_attrs, c, "Curve");
    bsl_ec_curve*    k  = bsl_ec_pick(ks, cv);
    if (k)
      bsl_ec_case(k, c);
    else
      skip++; /* curve not implemented: P-224, secp224k1 */
  }
  for (int i = 0; i < 3; i++)
    printf(
        "bssl ecdsa-%s: added %u pass %u fail %u skip 0\n", ks[i]->curve,
        ks[i]->added, ks[i]->pass, ks[i]->fail);
  printf(
      "bssl ecdsa-other: added %u pass 0 fail 0 skip %u (curve not "
      "implemented)\n",
      skip, skip);
}
