#include "crypto/symmetric/hash/hash/hmac.h"
#include "test.h"
#include "vectors/boringssl/bssl_vec.h"
#include "vectors/boringssl/hmac_tests.h"

/* BoringSSL crypto/hmac/hmac_tests.txt @
 * dd73e69a4e86fa178a4d19033c691e9b42cc1088. */

#define BSL_HM_BUF 256

typedef struct {
  const char* name;
  usz         len;
  void (*mac)(wired_span, wired_span, u8*);
  u32 added, pass, fail, skip;
} bsl_hm_alg;

static void bsl_hm_256(wired_span k, wired_span m, u8* o) {
  hmac_sha256(k, m, o);
}
static void bsl_hm_384(wired_span k, wired_span m, u8* o) {
  hmac_sha384(k, m, o);
}
static void bsl_hm_512(wired_span k, wired_span m, u8* o) {
  hmac_sha512(k, m, o);
}

static int bsl_hm_diff(const u8* a, const u8* b, usz n) {
  int d = 0;
  for (usz i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d;
}

/* 1 = MAC matches Output, 0 = mismatch, -1 = vector unreadable. */
static int bsl_hm_run(const bsl_hm_alg* a, const bssl_case* c) {
  u8               key[BSL_HM_BUF], in[BSL_HM_BUF], want[BSL_HM_BUF], got[64];
  const bssl_attr* t    = bssl_hmac_tests_attrs;
  ssz              kn   = bssl_bytes(bssl_get(t, c, "Key"), key, sizeof key);
  ssz              in_n = bssl_bytes(bssl_get(t, c, "Input"), in, sizeof in);
  ssz              wn = bssl_bytes(bssl_get(t, c, "Output"), want, sizeof want);
  if (kn < 0 || in_n < 0 || wn != (ssz)a->len) return -1;
  a->mac(wired_span_of(key, (usz)kn), wired_span_of(in, (usz)in_n), got);
  return bsl_hm_diff(got, want, a->len) == 0;
}

static void bsl_hm_case(bsl_hm_alg* a, const bssl_case* c) {
  int r = bsl_hm_run(a, c);
  a->added++;
  if (r == 1) {
    a->pass++;
    return;
  }
  a->fail++;
  printf(
      "FAIL hmac_tests.txt:%u-%u HMAC-%s mismatch (%d)\n", c->line_first,
      c->line_last, a->name, r);
  CHECK(r == 1);
}

static bsl_hm_alg* bsl_hm_find(bsl_hm_alg* t, const char* name) {
  for (; t->name; t++)
    if (bssl_streq(t->name, name)) return t;
  return 0;
}

void test_bssl_hmac(void) {
  /* MD5/SHA1/SHA224: no such hash in src/ -> skipped, counted. */
  bsl_hm_alg algs[] = {
      {"SHA256", 32, bsl_hm_256, 0, 0, 0, 0},
      {"SHA384", 48, bsl_hm_384, 0, 0, 0, 0},
      {"SHA512", 64, bsl_hm_512, 0, 0, 0, 0},
      {"MD5", 0, 0, 0, 0, 0, 0},
      {"SHA1", 0, 0, 0, 0, 0, 0},
      {"SHA224", 0, 0, 0, 0, 0, 0},
      {0, 0, 0, 0, 0, 0, 0}};
  for (u32 i = 0;
       i < sizeof bssl_hmac_tests_cases / sizeof bssl_hmac_tests_cases[0];
       i++) {
    const bssl_case* c = &bssl_hmac_tests_cases[i];
    bsl_hm_alg*      a =
        bsl_hm_find(algs, bssl_get(bssl_hmac_tests_attrs, c, "HMAC"));
    if (a->mac)
      bsl_hm_case(a, c);
    else
      a->skip++, a->added++;
  }
  for (bsl_hm_alg* a = algs; a->name; a++)
    printf(
        "bssl hmac-%s: added %u pass %u fail %u skip %u%s\n", a->name, a->added,
        a->pass, a->fail, a->skip,
        a->mac ? "" : " (hash/HMAC not implemented)");
}
