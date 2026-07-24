#include "crypto/asymmetric/ecc/p256sign/rfc6979.h"

#include "test.h"

static void r6979_hb32(const char* hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* RFC 6979 Appendix A.2.5: P-256, SHA-256, message "sample". */
static const char* R6979_X =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char* R6979_K =
    "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60";

static void test_rfc6979_sample_k(void) {
  u8 priv[32], want[32], h[32], k[32];
  r6979_hb32(R6979_X, priv);
  r6979_hb32(R6979_K, want);
  quic_sha256((const u8*)"sample", 6, h);
  quic_p256sign_k(priv, h, k);
  for (usz i = 0; i < 32; i++) CHECK(k[i] == want[i]);
}

/* Group order n (FIPS 186-4 D.1.2.3), big-endian 32 bytes, cross-checked by
 * hand against quic_p256_n's little-endian limbs the same way as
 * ecdsa_verify_test.c's P256_N. */
static const char* R6979_N =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
static const char* R6979_NM1 =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550";

/* RFC 6979 3.2 step h.3: the candidate k is accepted only if 1 <= k < q
 * (here q == quic_p256_n); anything outside that range must be re-derived.
 * ps_k_in_range is the guard the generation loop retries on; exercise its
 * boundaries directly since forcing HMAC to emit an out-of-range candidate
 * is not practical to construct. */
static void test_rfc6979_k_in_range_boundaries(void) {
  u8 zero[32] = {0}, n[32], nm1[32], one[32] = {0};
  one[31] = 1;
  r6979_hb32(R6979_N, n);
  r6979_hb32(R6979_NM1, nm1);
  CHECK(ps_k_in_range(zero) == 0); /* k == 0: below range */
  CHECK(ps_k_in_range(n) == 0);    /* k == n: at/above range */
  CHECK(ps_k_in_range(one) == 1);  /* k == 1: bottom of range, in */
  CHECK(ps_k_in_range(nm1) == 1);  /* k == n-1: top of range, in */
}

void test_rfc6979(void) {
  test_rfc6979_sample_k();
  test_rfc6979_k_in_range_boundaries();
}
