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

/* RFC 6979 Section 3.4: an in-range candidate that the caller rejects (e.g.
 * because it would yield r == 0) must not be accepted; generation must loop
 * to a further candidate instead. Drive quic_p256sign_k_retry with a stub
 * "ok" that rejects the first two candidates and accepts the third, and
 * confirm the result differs from the unconditional quic_p256sign_k (which
 * stops at the first in-range candidate) yet is still itself in range. */
typedef struct {
  int calls;
} r6979_reject_ctx;

static int r6979_reject_first_two(const u8 cand[32], void* vctx) {
  (void)cand;
  r6979_reject_ctx* c = (r6979_reject_ctx*)vctx;
  c->calls++;
  return c->calls > 2;
}

static void test_rfc6979_retry_skips_rejected_candidates(void) {
  u8               priv[32], h[32], k0[32], kr[32];
  r6979_reject_ctx ctx = {0};
  r6979_hb32(R6979_X, priv);
  quic_sha256((const u8*)"sample", 6, h);
  quic_p256sign_k(priv, h, k0);
  quic_p256sign_k_retry(priv, h, kr, r6979_reject_first_two, &ctx);
  CHECK(ctx.calls == 3);    /* rejected twice, accepted on the 3rd draw */
  CHECK(ps_k_in_range(kr)); /* the accepted candidate is still in range */
  int differs = 0;
  for (usz i = 0; i < 32; i++) differs |= (k0[i] != kr[i]);
  CHECK(differs != 0); /* retried past the first candidate k0 would use */
}

void test_rfc6979(void) {
  test_rfc6979_sample_k();
  test_rfc6979_k_in_range_boundaries();
  test_rfc6979_retry_skips_rejected_candidates();
}
