#include "crypto/asymmetric/ecc/bip340/bip340.h"

#include "common/bytes/util/ct.h"
#include "crypto/asymmetric/ecc/secp256k1/secp256k1.h"
#include "crypto/symmetric/hash/hash/sha256.h"

static void bip340_challenge(
    p256_fe e, const u8 sig[64], const u8 pk[32], const u8* msg, usz len);
static int bip340_inputs(
    secp256k1_pt* p, p256_fe s, const u8 pk[32], const u8 sig[64]);
static int bip340_r_ok(const secp256k1_pt* r, const u8 sig[64]);

/* e = int(hash_BIP0340/challenge(r || pk || m)) mod n, where
 * hash_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x). A 256-bit value
 * is < 2n (n > 2^255), so one conditional subtraction reduces it. */
static void bip340_challenge(
    p256_fe e, const u8 sig[64], const u8 pk[32], const u8* msg, usz len) {
  static const u8 tag[] = "BIP0340/challenge";
  u8              th[32], h[32];
  sha256_ctx      s;
  sha256_init(&s);
  sha256_update(&s, tag, sizeof(tag) - 1);
  sha256_final(&s, th);
  sha256_init(&s);
  sha256_update(&s, th, 32);
  sha256_update(&s, th, 32);
  sha256_update(&s, sig, 32);
  sha256_update(&s, pk, 32);
  sha256_update(&s, msg, len);
  sha256_final(&s, h);
  p256_fp_from_be(e, h);
  if (!p256_fp_lt(e, secp256k1_n)) {
    p256_fp_sub(e, (fpab){e, secp256k1_n}, secp256k1_n);
  }
}

/* P = lift_x(pk) (fails if not on the curve), r < p, s < n. */
static int bip340_inputs(
    secp256k1_pt* p, p256_fe s, const u8 pk[32], const u8 sig[64]) {
  p256_fe r;
  if (!secp256k1_lift_x(p, pk)) {
    return 0;
  }
  p256_fp_from_be(r, sig);
  p256_fp_from_be(s, sig + 32);
  return p256_fp_lt(r, secp256k1_p) && p256_fp_lt(s, secp256k1_n);
}

/* Fail if R is infinite, y(R) is odd, or x(R) != r. */
static int bip340_r_ok(const secp256k1_pt* r, const u8 sig[64]) {
  u8  x[32];
  int odd;
  if (!secp256k1_affine(x, &odd, r)) {
    return 0;
  }
  return !odd && ct_diff32(x, sig) == 0;
}

int bip340_verify(const u8 pk[32], const u8* msg, usz len, const u8 sig[64]) {
  secp256k1_pt p, g, r;
  p256_fe      s, e, ne, zero = {0};
  if (!bip340_inputs(&p, s, pk, sig)) {
    return 0;
  }
  bip340_challenge(e, sig, pk, msg, len);
  p256_fp_sub(ne, (fpab){zero, e}, secp256k1_n); /* -e mod n */
  secp256k1_base(&g);
  secp256k1_mul2(&r, (fpab){s, ne}, &g, &p);
  return bip340_r_ok(&r, sig);
}
