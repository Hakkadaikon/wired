#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"
#include "crypto/symmetric/hash/hash/sha512.h"
#include "crypto/wyc_pk_run.h"
#include "vectors/wycheproof/ecdsa_secp256r1_sha256_test.h"
#include "vectors/wycheproof/ecdsa_secp384r1_sha384_test.h"
#include "vectors/wycheproof/ecdsa_secp384r1_sha512_test.h"

/* Wycheproof testvectors_v1/ecdsa_secp{256r1_sha256,384r1_sha384,
 * 384r1_sha512}_test.json @ 3fa63dd0 (cases by tcId). The DER signature is
 * parsed by wired's own strict ecdsasig_decode (BER must be rejected), the
 * message is hashed by wired's SHA-2, and a digest longer than the group
 * order is cut to its leftmost bytes (FIPS 186-4 6.4.2, as bssl_ecdsa_test). */

#define WYC_EC_SIG 4352 /* longest DER signature in the files is 4205 bytes */
#define WYC_EC_MSG 32   /* longest msg in the files is 20 bytes */

typedef struct {
  const bssl_attr* attrs;
  usz              size; /* field / group order bytes */
  void (*hash)(const u8*, usz, u8*);
  int (*verify)(const u8*, const u8*, const u8*, const u8*, const u8*);
} wyc_ec_cfg;

/* Big-endian value in v as exactly size bytes: drop leading zero octets
 * (ASN.1 sign byte), zero-extend short values. 0 if it does not fit. */
static int wyc_ec_fit(u8* dst, usz size, const u8* v, usz n) {
  usz skip = 0;
  while (skip < n && n - skip > size && !v[skip]) skip++;
  if (n - skip > size) return 0;
  for (usz i = 0; i < size; i++) dst[i] = 0;
  for (usz i = skip; i < n; i++) dst[size - (n - skip) + (i - skip)] = v[i];
  return 1;
}

static int wyc_ec_coord(
    const wyc_ec_cfg* k, const wyc_case* c, const char* key, u8* out) {
  u8  raw[64];
  ssz n = bssl_bytes(wyc_get(k->attrs, c, key), raw, sizeof raw);
  return n > 0 && wyc_ec_fit(out, k->size, raw, (usz)n);
}

static int wyc_ec_key(const wyc_ec_cfg* k, const wyc_case* c, u8* x, u8* y) {
  return wyc_ec_coord(k, c, "g.publicKey.wx", x) &&
         wyc_ec_coord(k, c, "g.publicKey.wy", y);
}

static int wyc_ec_run(const wyc_ec_cfg* k, const wyc_case* c) {
  static u8 sig[WYC_EC_SIG];
  u8        msg[WYC_EC_MSG], x[48], y[48], r[48], s[48], h[64];
  ssz       m  = bssl_bytes(wyc_get(k->attrs, c, "msg"), msg, sizeof msg);
  ssz       sn = bssl_bytes(wyc_get(k->attrs, c, "sig"), sig, sizeof sig);
  if (m < 0 || sn < 0 || !wyc_ec_key(k, c, x, y)) return WYC_PK_BROKEN;
  k->hash(msg, (usz)m, h);
  if (!ecdsasig_decode(wired_span_of(sig, (usz)sn), r, s, k->size))
    return WYC_PK_REJECT;
  return k->verify(x, y, r, s, h) ? WYC_PK_ACCEPT : WYC_PK_REJECT;
}

static void wyc_h256(const u8* d, usz n, u8* o) { wired_sha256(d, n, o); }
static void wyc_h384(const u8* d, usz n, u8* o) { sha384(d, n, o); }
static void wyc_h512(const u8* d, usz n, u8* o) { sha512(d, n, o); }

static const wyc_ec_cfg wyc_ec_k256 = {
    wyc_ecdsa_secp256r1_sha256_test_attrs, 32, wyc_h256, ecdsa_p256_verify};
static const wyc_ec_cfg wyc_ec_k384 = {
    wyc_ecdsa_secp384r1_sha384_test_attrs, 48, wyc_h384, ecdsa_p384_verify};
/* SHA-512 digest is 64 bytes; ecdsa_p384_verify reads its leftmost 48. */
static const wyc_ec_cfg wyc_ec_k512 = {
    wyc_ecdsa_secp384r1_sha512_test_attrs, 48, wyc_h512, ecdsa_p384_verify};

static int wyc_ec_r256(const wyc_case* c) {
  return wyc_ec_run(&wyc_ec_k256, c);
}
static int wyc_ec_r384(const wyc_case* c) {
  return wyc_ec_run(&wyc_ec_k384, c);
}
static int wyc_ec_r512(const wyc_case* c) {
  return wyc_ec_run(&wyc_ec_k512, c);
}

#define WYC_N(a) ((u32)(sizeof a / sizeof a[0]))

static void wyc_ec_flag(const char* name, const char* flag) {
  wyc_pk_flag_rejected(
      name, wyc_ecdsa_secp256r1_sha256_test_cases,
      WYC_N(wyc_ecdsa_secp256r1_sha256_test_cases), wyc_ec_r256, flag);
  wyc_pk_flag_rejected(
      name, wyc_ecdsa_secp384r1_sha384_test_cases,
      WYC_N(wyc_ecdsa_secp384r1_sha384_test_cases), wyc_ec_r384, flag);
  wyc_pk_flag_rejected(
      name, wyc_ecdsa_secp384r1_sha512_test_cases,
      WYC_N(wyc_ecdsa_secp384r1_sha512_test_cases), wyc_ec_r512, flag);
}

void test_wyc_ecdsa(void) {
  /* ecdsa_secp256r1_sha256_test.json */
  wyc_pk_tally a = {.prim = "ecdsa-P-256/SHA-256", .file = "ecdsa_p256_sha256"};
  wyc_pk_all(
      &a, wyc_ecdsa_secp256r1_sha256_test_cases,
      WYC_N(wyc_ecdsa_secp256r1_sha256_test_cases), wyc_ec_r256);
  /* ecdsa_secp384r1_sha384_test.json */
  wyc_pk_tally b = {.prim = "ecdsa-P-384/SHA-384", .file = "ecdsa_p384_sha384"};
  wyc_pk_all(
      &b, wyc_ecdsa_secp384r1_sha384_test_cases,
      WYC_N(wyc_ecdsa_secp384r1_sha384_test_cases), wyc_ec_r384);
  /* ecdsa_secp384r1_sha512_test.json */
  wyc_pk_tally c = {.prim = "ecdsa-P-384/SHA-512", .file = "ecdsa_p384_sha512"};
  wyc_pk_all(
      &c, wyc_ecdsa_secp384r1_sha512_test_cases,
      WYC_N(wyc_ecdsa_secp384r1_sha512_test_cases), wyc_ec_r512);
  /* the same three files, result=invalid cases per flag */
  wyc_ec_flag(
      "test_wyc_ecdsa_invalid_BerEncodedSignature_rejected",
      "BerEncodedSignature");
  wyc_ec_flag(
      "test_wyc_ecdsa_invalid_InvalidEncoding_rejected", "InvalidEncoding");
  wyc_ec_flag(
      "test_wyc_ecdsa_invalid_IntegerOverflow_rejected", "IntegerOverflow");
  wyc_ec_flag("test_wyc_ecdsa_invalid_RangeCheck_rejected", "RangeCheck");
  wyc_ec_flag("test_wyc_ecdsa_invalid_MissingZero_rejected", "MissingZero");
}
