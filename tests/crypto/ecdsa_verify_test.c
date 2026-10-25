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
  wired_sha256((const u8*)"sample", 6, h);
}

/* Valid signature verifies. */
static void test_ecdsa_valid(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  CHECK(ecdsa_p256_verify(qx, qy, r, s, h) == 1);
}

/* Flipping a hash bit must reject. */
static void test_ecdsa_bad_hash(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  h[0] ^= 0x01;
  CHECK(ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* Flipping an s bit must reject. */
static void test_ecdsa_bad_sig(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  s[31] ^= 0x01;
  CHECK(ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* r = 0 is out of range and must reject. */
static void test_ecdsa_zero_r(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  for (usz i = 0; i < 32; i++) {
    r[i] = 0;
  }
  CHECK(ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* Group order n (FIPS 186-4 D.1.2.3 / RFC 6090), big-endian 32 bytes:
 * ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.
 * Cross-checked against p256_n's little-endian limbs
 * (f3b9cac2fc632551, bce6faada7179e84, ffffffffffffffff, ffffffff00000000)
 * by hand: limb i occupies bytes [32-8*(i+1), 32-8*i) big-endian. */
static const char* P256_N =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

/* RFC 6090 / FIPS 186-4 6.4.2: a signature component >= n is out of the
 * valid range [1, n-1] and MUST be rejected, even with an otherwise-valid
 * counterpart and hash. */
static void test_ecdsa_s_ge_n(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  ecdsa_hb32(P256_N, s); /* s == n, one past the top of the valid range */
  CHECK(ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* Same boundary on r: r == n must also reject. */
static void test_ecdsa_r_ge_n(void) {
  u8 qx[32], qy[32], r[32], s[32], h[32];
  load_vec(qx, qy, r, s, h);
  ecdsa_hb32(P256_N, r);
  CHECK(ecdsa_p256_verify(qx, qy, r, s, h) == 0);
}

/* Q = (0, y) is on P-256 (0^3 - 3*0 + b = b is a square mod p). With
 * u1 = u2 = 1 the forged-by-construction signature r = s = e = (G+Q).x mod n
 * verifies (w = 1/r, u1 = e*w = 1, u2 = r*w = 1). Values computed with
 * Python big integers from the FIPS 186-4 D.1.2.3 domain parameters. */
static const char* QX0 =
    "0000000000000000000000000000000000000000000000000000000000000000";
/* x = p: the same field element as 0, but not less than p. */
static const char* QXP =
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
static const char* QY0 =
    "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4";
static const char* RSH0 =
    "00486efab89170d45f6160cbc7d034a9309d479ae02982a3a0c135a210379e6f";

static int ecdsa_x0_verify(const char* qxhex, u8 ybump) {
  u8 qx[32], qy[32], rs[32];
  ecdsa_hb32(qxhex, qx);
  ecdsa_hb32(QY0, qy);
  ecdsa_hb32(RSH0, rs);
  qy[31] ^= ybump;
  return ecdsa_p256_verify(qx, qy, rs, rs, rs);
}

/* RFC 6090 3: the canonical x = 0 key verifies; the alias x = p (not an
 * element of Fp) must be rejected, as must the off-curve (0, y ^ 1). */
static void test_ecdsa_coord_ge_p_and_off_curve(void) {
  CHECK(ecdsa_x0_verify(QX0, 0) == 1);
  CHECK(ecdsa_x0_verify(QXP, 0) == 0);
  CHECK(ecdsa_x0_verify(QX0, 1) == 0);
}

void test_ecdsa_verify(void) {
  test_ecdsa_valid();
  test_ecdsa_bad_hash();
  test_ecdsa_bad_sig();
  test_ecdsa_zero_r();
  test_ecdsa_s_ge_n();
  test_ecdsa_r_ge_n();
  test_ecdsa_coord_ge_p_and_off_curve();
}
