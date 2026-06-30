#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"

static void psign_hb32(const char *hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* RFC 6979 Appendix A.2.5 key/public point for "sample". s is the low-S
 * normalized form (n - s_rfc) since the A.2.5 s exceeds n/2. */
static const char *PS_X =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char *PS_QX =
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
static const char *PS_QY =
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
static const char *PS_R =
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
static const char *PS_S =
    "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9";

/* n/2 = floor(n/2) big-endian; low-S requires s <= n/2. */
static const char *PS_NHALF =
    "7fffffff800000007fffffffffffffffde737d56d38bcca7179b7a210a88a3dd";

/* Deterministic signature matches the hand-derived RFC 6979 golden. */
static void test_p256sign_known_vector(void) {
  u8 priv[32], h[32], r[32], s[32], wr[32], ws[32];
  psign_hb32(PS_X, priv);
  psign_hb32(PS_R, wr);
  psign_hb32(PS_S, ws);
  quic_sha256((const u8 *)"sample", 6, h);
  CHECK(quic_p256sign_sign(priv, h, r, s) == 1);
  for (usz i = 0; i < 32; i++) CHECK(r[i] == wr[i]);
  for (usz i = 0; i < 32; i++) CHECK(s[i] == ws[i]);
}

/* Self-produced signature verifies under the existing verifier (round-trip). */
static void ps_roundtrip(const u8 *msg, usz len) {
  u8 priv[32], qx[32], qy[32], h[32], r[32], s[32];
  psign_hb32(PS_X, priv);
  psign_hb32(PS_QX, qx);
  psign_hb32(PS_QY, qy);
  quic_sha256(msg, len, h);
  CHECK(quic_p256sign_sign(priv, h, r, s) == 1);
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, s, h) == 1);
}

static void test_p256sign_ps_roundtrip(void) {
  ps_roundtrip((const u8 *)"sample", 6);
  ps_roundtrip((const u8 *)"test", 4);
  ps_roundtrip((const u8 *)"", 0);
}

/* 1 if a <= b (big-endian 32-byte). */
static int le32(const u8 a[32], const u8 b[32]) {
  for (usz i = 0; i < 32; i++) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return 1;
}

/* Low-S: s is never greater than n/2, and r, s are non-zero. */
static void test_p256sign_low_s(void) {
  u8 priv[32], h[32], r[32], s[32], nhalf[32], zero[32] = {0};
  psign_hb32(PS_X, priv);
  psign_hb32(PS_NHALF, nhalf);
  quic_sha256((const u8 *)"test", 4, h);
  CHECK(quic_p256sign_sign(priv, h, r, s) == 1);
  CHECK(le32(s, nhalf) == 1);
  CHECK(le32(r, zero) == 0);
  CHECK(le32(s, zero) == 0);
}

/* Verifier rejects r == 0 and s == 0: a zero scalar drops the key binding,
 * so a forged (0, s) or (r, 0) must never verify (FIPS 186-4 6.4.2). */
static void test_p256sign_verify_rejects_zero(void) {
  u8 qx[32], qy[32], h[32], r[32], s[32], zero[32] = {0};
  psign_hb32(PS_QX, qx);
  psign_hb32(PS_QY, qy);
  psign_hb32(PS_R, r);
  psign_hb32(PS_S, s);
  quic_sha256((const u8 *)"sample", 6, h);
  CHECK(quic_ecdsa_p256_verify(qx, qy, zero, s, h) == 0);
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, zero, h) == 0);
}

void test_p256sign(void) {
  test_p256sign_known_vector();
  test_p256sign_ps_roundtrip();
  test_p256sign_low_s();
  test_p256sign_verify_rejects_zero();
}
