#include "test.h"

static u8 sgn_hexnib(char c) { return (u8)(c <= '9' ? c - '0' : c - 'a' + 10); }

static void sgn_hexbytes(const char* hex, u8* out, usz n) {
  for (usz i = 0; i < n; i++)
    out[i] = (u8)((sgn_hexnib(hex[i * 2]) << 4) | sgn_hexnib(hex[i * 2 + 1]));
}

/* One RFC 8032 7.1 vector: seed -> public, (seed,msg) -> signature, and the
 * produced signature verifies. */
static void sign_vector(
    const char* seed,
    const char* pub,
    const char* msg,
    usz         msg_len,
    const char* sig) {
  u8 sd[32], pk[32], want_pk[32], M[64], want_sig[64], got_pk[32], got_sig[64];
  sgn_hexbytes(seed, sd, 32);
  sgn_hexbytes(pub, want_pk, 32);
  sgn_hexbytes(sig, want_sig, 64);
  if (msg_len) sgn_hexbytes(msg, M, msg_len);

  ed25519_keypair(sd, got_pk);
  for (usz i = 0; i < 32; i++) CHECK(got_pk[i] == want_pk[i]);

  ed25519_sign(sd, M, msg_len, got_sig);
  for (usz i = 0; i < 64; i++) CHECK(got_sig[i] == want_sig[i]);

  for (usz i = 0; i < 32; i++) pk[i] = want_pk[i];
  CHECK(ed25519_verify(got_sig, M, msg_len, pk) == 1);
}

/* RFC 8032 7.1 TEST 1: empty message. */
static void test_ed25519_sign_test1(void) {
  sign_vector(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", 0,
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
      "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
}

/* RFC 8032 7.1 TEST 2: one-byte message 0x72. */
static void test_ed25519_sign_test2(void) {
  sign_vector(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      1,
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69d"
      "a085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

/* RFC 8032 7.1 TEST 3: two-byte message 0xaf82. */
static void test_ed25519_sign_test3(void) {
  sign_vector(
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82", 2,
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
      "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
}

/* RFC 8032 7.1 TEST(SHA(abc)): 64-byte message equal to SHA-512("abc").
 * Message value cross-derived independently (not copied from a single
 * source): computed as SHA-512 of the three ASCII bytes 'a','b','c' and
 * confirmed to match the RFC's own printed MESSAGE field byte-for-byte,
 * and the whole vector (seed -> pub, (seed,msg) -> sig) was independently
 * re-derived with a from-scratch pure Python Ed25519 implementation before
 * being transcribed here. */
static void test_ed25519_sign_test_sha_abc(void) {
  sign_vector(
      "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
      "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      64,
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
      "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
}

/* RFC 8032 L, the Ed25519 group order, little-endian 32 bytes (5.1):
 * L = 2^252 + 27742317777372353535851937790883648493. Cross-checked by hand
 * against ed25519_sign.c's ORDER_L limb-by-limb (bytes 0-15 match the low
 * summand's little-endian encoding, byte 31 == 0x10 from the 2^252 term). */
static const char* ORDER_L_HEX =
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/* RFC 8032 5.1.7 step 3 / verify: S is decoded as a scalar and MUST satisfy
 * 0 <= S < L; otherwise the signature is rejected outright, before any group
 * arithmetic. Boundary: S == L is one past the top of the valid range. */
static void test_ed25519_verify_s_eq_l_rejected(void) {
  u8 sd[32], pk[32], sig[64];
  sgn_hexbytes(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", sd,
      32);
  ed25519_keypair(sd, pk);
  ed25519_sign(sd, (const u8*)"", 0, sig);
  sgn_hexbytes(ORDER_L_HEX, sig + 32, 32); /* overwrite S with L itself */
  CHECK(ed25519_verify(sig, (const u8*)"", 0, pk) == 0);
}

void test_ed25519_sign(void) {
  test_ed25519_sign_test1();
  test_ed25519_sign_test2();
  test_ed25519_sign_test3();
  test_ed25519_sign_test_sha_abc();
  test_ed25519_verify_s_eq_l_rejected();
}
