#include "common/bytes/util/bytes.h"
#include "crypto/asymmetric/rsa/pss.h"
#include "crypto/asymmetric/rsa/rsa_pss_verify.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"
#include "crypto/symmetric/hash/hash/sha512.h"
#include "psschain_golden.h"
#include "test.h"

/* 2048-bit RSA-PSS / SHA-256 / MGF1-SHA-256 / saltLen=32 vector. Key generated
 * with the Python cryptography library (e=65537); sig = sign(msg, PSS) over
 * SHA-256("quic_vibe rsa-pss test vector"); the library verified it before
 * extraction. n, sig are big-endian; hash is SHA-256(msg). The message keeps
 * the repository's pre-rename name: it is the actual signed input, so
 * renaming it would invalidate the vector. */
static const u8 pss_n[256] = {
    0xcb, 0x5b, 0x08, 0x46, 0x33, 0x5c, 0x6f, 0x29, 0xe9, 0x70, 0x56, 0x69,
    0xc7, 0x82, 0x86, 0x54, 0x0e, 0x40, 0x97, 0x07, 0x61, 0x27, 0x63, 0x84,
    0x49, 0x34, 0xe5, 0xe5, 0x30, 0xdb, 0x9f, 0x18, 0xc4, 0x7a, 0x50, 0x33,
    0xeb, 0x09, 0x50, 0xbe, 0x03, 0x70, 0xdc, 0x72, 0xed, 0x79, 0x80, 0x9a,
    0xab, 0x15, 0xce, 0xac, 0x53, 0x19, 0x86, 0x00, 0xd8, 0xb4, 0xa8, 0x85,
    0xec, 0xee, 0x16, 0x7e, 0xb3, 0x46, 0x8d, 0x54, 0x9d, 0x05, 0xdc, 0x3d,
    0x74, 0xe5, 0xfc, 0x4c, 0xb8, 0xf8, 0x45, 0xee, 0x7f, 0xb5, 0xd9, 0x6e,
    0xf5, 0x1b, 0x70, 0x9f, 0xf2, 0x1a, 0x2b, 0x3e, 0xcb, 0xd6, 0x0c, 0x29,
    0xf2, 0x2b, 0x45, 0x0b, 0xbd, 0xf3, 0xdc, 0xd8, 0xf1, 0x5f, 0x51, 0xe2,
    0x43, 0xb7, 0x73, 0xa7, 0xc0, 0x2b, 0xd2, 0x7a, 0x3f, 0x29, 0xb1, 0x4c,
    0xae, 0x91, 0xfd, 0x60, 0x57, 0xe3, 0x23, 0xa3, 0xd2, 0x72, 0x3d, 0xc1,
    0x15, 0x98, 0x01, 0x8d, 0x17, 0x6f, 0xa1, 0x01, 0x97, 0x75, 0x63, 0x8f,
    0x7c, 0xf1, 0x64, 0xeb, 0xa2, 0x60, 0xdb, 0x5f, 0x82, 0xca, 0xb8, 0xc9,
    0xde, 0x3c, 0x5d, 0x11, 0x6a, 0x83, 0x73, 0x69, 0xf4, 0x7b, 0xfe, 0x08,
    0x46, 0xa6, 0x59, 0x52, 0xcb, 0x77, 0x17, 0x6c, 0x29, 0x73, 0x95, 0xf2,
    0x58, 0x3b, 0x59, 0xa1, 0x95, 0x86, 0x8b, 0x20, 0x27, 0x15, 0xbb, 0x0f,
    0xda, 0xda, 0xb8, 0xd9, 0xd0, 0x69, 0x7a, 0x5f, 0xe4, 0x4a, 0x09, 0xfe,
    0x8d, 0xbe, 0xf4, 0x05, 0xdc, 0x2e, 0xb2, 0x77, 0x2f, 0x25, 0xc3, 0x7c,
    0x39, 0xd7, 0x17, 0xde, 0x7c, 0xc0, 0x05, 0x2a, 0xc8, 0xa3, 0xf6, 0x7d,
    0x13, 0x53, 0x68, 0x39, 0x65, 0xf0, 0x43, 0xd9, 0x63, 0x42, 0xff, 0x8a,
    0x68, 0x76, 0x55, 0x3c, 0x50, 0xd9, 0x36, 0xbb, 0x45, 0x6d, 0x38, 0xc3,
    0xbc, 0xd8, 0xe0, 0x4f,
};
static const u8 pss_sig[256] = {
    0x65, 0x5f, 0x23, 0xdc, 0x23, 0x9e, 0x37, 0x98, 0x09, 0x5a, 0xf1, 0xc9,
    0x36, 0x5c, 0xd2, 0xa1, 0xc0, 0xdf, 0xf8, 0xc3, 0x45, 0xf8, 0xc4, 0xbc,
    0xa5, 0x27, 0x92, 0xe7, 0x90, 0xb2, 0x94, 0x5b, 0x41, 0xdd, 0x05, 0x5f,
    0x6b, 0x7d, 0xe7, 0xd2, 0x93, 0x53, 0xec, 0xb7, 0x24, 0x63, 0x17, 0x3f,
    0xf2, 0x73, 0x75, 0x84, 0x04, 0x1a, 0x64, 0x99, 0xe9, 0xfe, 0x86, 0x63,
    0x5c, 0x72, 0x74, 0xb1, 0xaf, 0x9f, 0xcd, 0xc3, 0x28, 0xb0, 0xb5, 0x3b,
    0x75, 0xac, 0xf8, 0xac, 0xd2, 0xa1, 0xdb, 0x94, 0x5e, 0x80, 0x23, 0x44,
    0xc7, 0xc8, 0xc7, 0x46, 0x69, 0xd0, 0x6f, 0x48, 0x76, 0x67, 0x27, 0x54,
    0x80, 0x19, 0x71, 0xae, 0x2e, 0xb7, 0xe1, 0xd5, 0xf4, 0x5b, 0x66, 0xb3,
    0x2c, 0x10, 0xfa, 0xe1, 0x7a, 0x72, 0x8f, 0x4a, 0x5a, 0xa2, 0x63, 0x4a,
    0xc9, 0x4e, 0x78, 0xe8, 0x46, 0x8b, 0x90, 0x12, 0x54, 0xeb, 0xe3, 0x2a,
    0xe9, 0xc0, 0xa9, 0xa4, 0x1d, 0x17, 0x8b, 0x20, 0xb6, 0x2a, 0xb4, 0x69,
    0xb0, 0x22, 0xeb, 0x19, 0x41, 0xb2, 0xe4, 0x45, 0xec, 0x9e, 0x1f, 0x58,
    0xe3, 0xc1, 0x57, 0x39, 0x1a, 0xe2, 0xf5, 0x87, 0x3f, 0xd9, 0x59, 0x92,
    0x23, 0x41, 0x1f, 0xeb, 0x0f, 0xdd, 0x45, 0x79, 0x50, 0xbd, 0xda, 0xe5,
    0x0b, 0x4a, 0x3d, 0x4e, 0xe7, 0x85, 0xbe, 0x51, 0x0f, 0x4f, 0x3c, 0xd8,
    0x23, 0x13, 0x4b, 0xdd, 0xd3, 0xb1, 0x02, 0x30, 0x22, 0x30, 0x59, 0x0f,
    0x08, 0xbc, 0x68, 0x44, 0x04, 0xa2, 0xae, 0x0e, 0x1a, 0x85, 0xe2, 0xc8,
    0x1c, 0xab, 0x22, 0x8b, 0xc7, 0x6b, 0x8b, 0x8a, 0xe5, 0xe9, 0xc6, 0x71,
    0x2f, 0x36, 0xbc, 0x63, 0xf8, 0x9a, 0x36, 0x44, 0xab, 0x2c, 0x12, 0x6c,
    0x4b, 0x01, 0xea, 0x6d, 0x81, 0xf7, 0x8f, 0x19, 0x42, 0xcf, 0x4e, 0xe8,
    0xa7, 0x0f, 0x1c, 0xc1,
};
static const u8 pvt_e[3] = {0x01, 0x00, 0x01};

static const u8 pss_hash[32] = {
    0x79, 0xf9, 0x34, 0x04, 0x12, 0xf2, 0x3d, 0xfb, 0xb0, 0xdb, 0x5d,
    0xb8, 0xe2, 0x0c, 0x42, 0x6a, 0x16, 0x2f, 0xed, 0x43, 0x97, 0xcd,
    0x3a, 0x9d, 0xdc, 0x12, 0x7f, 0x89, 0xdf, 0x9a, 0xc7, 0x59,
};

static const rsa_pub pvt_pub = {{pss_n, 256}, {pvt_e, 3}};

static void test_rsa_pss_valid(void) {
  CHECK(
      rsa_pss_verify(
          &pvt_pub, (wired_span){pss_sig, 256}, (wired_span){pss_hash, 32}) ==
      1);
}

/* A flipped signature byte must fail. */
static void test_rsa_pss_tampered_sig(void) {
  u8 bad[256];
  for (usz i = 0; i < 256; i++) {
    bad[i] = pss_sig[i];
  }
  bad[128] ^= 0x01;
  CHECK(
      rsa_pss_verify(
          &pvt_pub, (wired_span){bad, 256}, (wired_span){pss_hash, 32}) == 0);
}

/* A wrong message hash must fail. */
static void test_rsa_pss_wrong_hash(void) {
  u8 h[32];
  for (usz i = 0; i < 32; i++) {
    h[i] = pss_hash[i];
  }
  h[0] ^= 0xff;
  CHECK(
      rsa_pss_verify(
          &pvt_pub, (wired_span){pss_sig, 256}, (wired_span){h, 32}) == 0);
}

/* Size guards: bad lengths are rejected. */
static void test_rsa_pss_sizes(void) {
  CHECK(
      rsa_pss_verify(
          &pvt_pub, (wired_span){pss_sig, 255}, (wired_span){pss_hash, 32}) ==
      0);
  CHECK(
      rsa_pss_verify(
          &pvt_pub, (wired_span){pss_sig, 256}, (wired_span){pss_hash, 31}) ==
      0);
  /* emsa_pss_verify guards its own EM buffers: > 512 octets or a non-SHA-256
   * digest is rejected */
  static const u8          pssv_big[513] = {0};
  static const rsa_pss_cfg s256          = {{wired_sha256, 32}, 32};
  CHECK(
      emsa_pss_verify(
          (wired_span){pssv_big, 513}, 8 * 513 - 1, (wired_span){pss_hash, 32},
          &s256) == 0);
  CHECK(
      emsa_pss_verify(
          (wired_span){pss_sig, 256}, 2047, (wired_span){pss_hash, 20},
          &s256) == 0);
}

/* RFC 8017 8.1.2: modBits of a modulus with leading zero octets and a short
 * top octet, and of the all-zero modulus. */
static void test_rsa_pss_modbits(void) {
  static const u8 n9[3] = {0x00, 0x01, 0xff}, n0[2] = {0};
  CHECK(rsa_modbits(n9, 3) == 9);
  CHECK(rsa_modbits(n0, 2) == 0);
}

/* The RSA-2048 root of psschain_golden.h. */
static const rsa_pub pss_root_pub = {{psschain_n, 256}, {pvt_e, 3}};

/* Verify sig over msg under pss_root_pub with digest h and salt length. */
static int pss_vec(const char* msg, rsa_digest h, usz salt, const u8* sig) {
  u8          d[65];
  rsa_pss_cfg cfg = {h, salt};
  h.fn((const u8*)msg, wired_cstr_len(msg), d);
  return rsa_pss_verify_cfg(
      &pss_root_pub, (wired_span){sig, 256}, (wired_span){d, h.len}, &cfg);
}

static const rsa_digest pss_d256 = {wired_sha256, 32};
static const rsa_digest pss_d384 = {sha384, 48};
static const rsa_digest pss_d512 = {sha512, 64};

/* RFC 8017 8.1.2 with SHA-384 / MGF1-SHA-384 / salt 48, SHA-512 /
 * MGF1-SHA-512 / salt 64, and SHA-256 with a non-hLen salt of 20. */
static void test_rsa_pss_other_hashes(void) {
  CHECK(pss_vec("wired rsa-pss h384 vector", pss_d384, 48, psschain_sig384));
  CHECK(pss_vec("wired rsa-pss h512 vector", pss_d512, 64, psschain_sig512));
  CHECK(pss_vec(
      "wired rsa-pss h256s20 vector", pss_d256, 20, psschain_sig256s20));
}

/* The same signatures under the wrong salt length, digest or message. */
static void test_rsa_pss_other_mismatch(void) {
  CHECK(!pss_vec("wired rsa-pss h384 vector", pss_d384, 32, psschain_sig384));
  CHECK(!pss_vec("wired rsa-pss h384 vector", pss_d512, 48, psschain_sig384));
  CHECK(!pss_vec("wired rsa-pss h512 vector", pss_d512, 0, psschain_sig512));
  CHECK(!pss_vec("wired rsa-pss h384 vectoR", pss_d384, 48, psschain_sig384));
  CHECK(!pss_vec(
      "wired rsa-pss h256s20 vector", pss_d256, 32, psschain_sig256s20));
}

/* RFC 8017 9.1.2 step 3: emLen < hLen + sLen + 2 is inconsistent; a digest
 * longer than 64 octets is not supported. */
static void test_rsa_pss_cfg_bounds(void) {
  static const rsa_digest d65 = {sha512, 65};
  CHECK(!pss_vec(
      "wired rsa-pss h512 vector", pss_d512, 256 - 64 - 1, psschain_sig512));
  CHECK(!pss_vec("wired rsa-pss h512 vector", d65, 64, psschain_sig512));
}

/* RFC 8017 8.1.2 step 2c / 9.1.2: with modBits = 2049 (emLen = k - 1) a
 * valid signature verifies, but one whose m = s^e mod n needs k octets is
 * "integer too large" -- even though its low emLen octets are a valid EM. */
static void test_rsa_pss_em_too_large(void) {
  static const rsa_pub pub   = {{psschain_n2049, 257}, {pvt_e, 3}};
  static const char    msg[] = "wired rsa-pss 2049 vector";
  u8                   d[32];
  wired_sha256((const u8*)msg, sizeof(msg) - 1, d);
  CHECK(
      rsa_pss_verify(
          &pub, (wired_span){psschain_sig2049, 257}, (wired_span){d, 32}) == 1);
  CHECK(
      rsa_pss_verify(
          &pub, (wired_span){psschain_sig2049big, 257}, (wired_span){d, 32}) ==
      0);
}

/* A synthetic EMSA-PSS encoding (RFC 8017 9.1.1 steps 4-12) under SHA-256,
 * sLen 32, emLen 128, emBits 1023: maskedDB || H || 0xbc. ps_byte and
 * one_byte stand in for PS's first octet and the 0x01 separator so a single
 * step-10 field can be broken while H stays the true Hash(M'). */
#define PSSE_LEN 128
#define PSSE_DB (PSSE_LEN - 32 - 1)

static const rsa_pss_cfg psse_cfg = {{wired_sha256, 32}, 32};

static void psse_build(u8* em, const u8* mhash, u8 ps_byte, u8 one_byte) {
  u8 m[8 + 32 + 32] = {0}, mask[PSSE_DB];
  for (usz i = 0; i < 32; i++) {
    m[8 + i]  = mhash[i];
    m[40 + i] = (u8)(0xa0 + i); /* salt */
  }
  for (usz i = 0; i < PSSE_DB; i++) {
    em[i] = 0;
  }
  em[0]                = ps_byte;
  em[PSSE_DB - 32 - 1] = one_byte;
  for (usz i = 0; i < 32; i++) {
    em[PSSE_DB - 32 + i] = m[40 + i];
  }
  wired_sha256(m, sizeof m, em + PSSE_DB);
  rsa_mgf1(
      psse_cfg.h, (wired_span){em + PSSE_DB, 32}, (wired_mspan){mask, PSSE_DB});
  for (usz i = 0; i < PSSE_DB; i++) {
    em[i] ^= mask[i];
  }
  em[0] &= 0x7f;
  em[PSSE_LEN - 1] = 0xbc;
}

static int psse_verify(const u8* em, const u8* mhash) {
  return emsa_pss_verify(
      (wired_span){em, PSSE_LEN}, 8 * PSSE_LEN - 1, (wired_span){mhash, 32},
      &psse_cfg);
}

/* The untouched synthetic encoding is consistent, so each test below fails
 * only on the one field it breaks. */
static void test_rsa_pss_em_synthetic_ok(void) {
  u8 em[PSSE_LEN];
  psse_build(em, pss_hash, 0x00, 0x01);
  CHECK(psse_verify(em, pss_hash) == 1);
}

/* RFC 8017 9.1.2 step 4: the rightmost octet is not 0xbc. */
static void test_rsa_pss_em_trailer_rejected(void) {
  u8 em[PSSE_LEN];
  psse_build(em, pss_hash, 0x00, 0x01);
  em[PSSE_LEN - 1] = 0xbd;
  CHECK(psse_verify(em, pss_hash) == 0);
}

/* RFC 8017 9.1.2 step 6: the leftmost 8emLen - emBits bit of maskedDB is
 * set. Step 9 clears that bit anyway, so the rest still decodes to a
 * consistent DB -- only step 6 can reject it. */
static void test_rsa_pss_em_top_bit_rejected(void) {
  u8 em[PSSE_LEN];
  psse_build(em, pss_hash, 0x00, 0x01);
  em[0] |= 0x80;
  CHECK(psse_verify(em, pss_hash) == 0);
}

/* RFC 8017 9.1.2 step 10: a nonzero PS octet, and a separator other than
 * 0x01, each with H = Hash(M') still correct (step 14 would accept). */
static void test_rsa_pss_em_padding_rejected(void) {
  u8 em[PSSE_LEN];
  psse_build(em, pss_hash, 0x01, 0x01);
  CHECK(psse_verify(em, pss_hash) == 0);
  psse_build(em, pss_hash, 0x00, 0x02);
  CHECK(psse_verify(em, pss_hash) == 0);
}

void test_rsa_pss(void) {
  test_rsa_pss_em_synthetic_ok();
  test_rsa_pss_em_trailer_rejected();
  test_rsa_pss_em_top_bit_rejected();
  test_rsa_pss_em_padding_rejected();
  test_rsa_pss_em_too_large();
  test_rsa_pss_other_hashes();
  test_rsa_pss_other_mismatch();
  test_rsa_pss_cfg_bounds();
  test_rsa_pss_valid();
  test_rsa_pss_tampered_sig();
  test_rsa_pss_wrong_hash();
  test_rsa_pss_sizes();
  test_rsa_pss_modbits();
}
