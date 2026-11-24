#include "crypto/asymmetric/ecc/bip340/bip340.h"

#include "test.h"
#include "vectors/bip340/bip340_vectors.h"
#include "vectors/boringssl/bssl_vec.h"

/* Every row of BIP-340 test-vectors.csv: the verification result must
 * match (valid rows, signing-side rows and every invalid case: pubkey not
 * on the curve, r >= p, s >= n, R at infinity, odd y(R), wrong x(R),
 * negated message / s, pubkey >= p). Messages are 0..100 bytes. */
static void test_bip340_csv(void) {
  usz n = sizeof(bip340_vecs) / sizeof(bip340_vecs[0]);
  CHECK(n == 19);
  for (usz i = 0; i < n; i++) {
    const bip340_vec* v = &bip340_vecs[i];
    u8                pk[32], sig[64], msg[128];
    ssz               ml = bssl_hex(v->msg, msg, sizeof(msg));
    CHECK(bssl_hex(v->pk, pk, 32) == 32);
    CHECK(bssl_hex(v->sig, sig, 64) == 64);
    CHECK(ml >= 0);
    if (bip340_verify(pk, msg, (usz)ml, sig) != v->ok) {
      printf("bip340 row %d (%s)\n", v->index, v->comment);
      CHECK(0);
    }
  }
}

/* A valid row stops verifying when any one of r, s or the message flips. */
static void test_bip340_tamper(void) {
  const bip340_vec* v     = &bip340_vecs[1];
  static const usz  at[3] = {0, 40, 64};
  for (usz i = 0; i < 3; i++) {
    u8 pk[32], buf[96];
    bssl_hex(v->pk, pk, 32);
    bssl_hex(v->sig, buf, 64);
    bssl_hex(v->msg, buf + 64, 32);
    buf[at[i]] ^= 1;
    CHECK(bip340_verify(pk, buf + 64, 32, buf) == 0);
  }
}

void test_bip340(void) {
  test_bip340_csv();
  test_bip340_tamper();
}
