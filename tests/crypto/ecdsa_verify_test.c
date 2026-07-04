#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"

#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"

static void ecdsa_hb32(const char* hex, u8 out[32]) {
  for (usz i = 0; i < 32; i++) {
    u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
    out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                  (lo <= '9' ? lo - '0' : lo - 'a' + 10));
  }
}

/* RFC 6979 Appendix A.2.5: P-256, key and signature over "sample"/SHA-256. */
static const char* QX =
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
static const char* QY =
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
static const char* SR =
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716";
static const char* SS =
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";

static void load_vec(u8 qx[32], u8 qy[32], u8 r[32], u8 s[32], u8 h[32]) {
  ecdsa_hb32(QX, qx);
  ecdsa_hb32(QY, qy);
  ecdsa_hb32(SR, r);
  ecdsa_hb32(SS, s);
  quic_sha256((const u8*)"sample", 6, h);
}

/* Valid signature verifies. */
static void test_ecdsa_valid(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, s, h) == 1);
}

/* Flipping a hash bit must reject. */
static void test_ecdsa_bad_hash(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  h[0] ^= 0x01;
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* Flipping an s bit must reject. */
static void test_ecdsa_bad_sig(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  s[31] ^= 0x01;
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* r = 0 is out of range and must reject. */
static void test_ecdsa_zero_r(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  for (usz i = 0; i < 32; i++) r[i] = 0;
  CHECK(quic_ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

void test_ecdsa_verify(void) {
  test_ecdsa_valid();
  test_ecdsa_bad_hash();
  test_ecdsa_bad_sig();
  test_ecdsa_zero_r();
}
