#include "common/bytes/util/num.h"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p521/ecdsa_verify.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/trust/castore/chainverify_impl.h"

/* FIPS 186-4 6.4: a digest wider than the P-256 order uses its leftmost 32
 * bytes (a 32-byte digest is copied whole). */
static void chv_hash_to_scalar32(const u8* hash, u8 h32[32]) {
  for (usz i = 0; i < 32; i++) {
    h32[i] = hash[i];
  }
}

static int chv_verify_p256(wired_span key, wired_span sig, wired_span hash) {
  u8 x[32], y[32], r[32], s[32], h32[32];
  if (!x509_ec_pubkey(key, x, y)) {
    return 0;
  }
  if (!ecdsasig_decode(sig, r, s, 32)) {
    return 0;
  }
  chv_hash_to_scalar32(hash.p, h32);
  return ecdsa_p256_verify(x, y, r, s, h32);
}

/* FIPS 186-4 6.4: a digest wider than the P-384 order (SHA-512) uses its
 * leftmost 48 bytes; a shorter one is left-zero-extended into 48 bytes. */
static void chv_hash_to_scalar48(wired_span hash, u8 h48[48]) {
  usz n   = (usz)u64_min(hash.n, 48);
  usz off = 48 - n;
  for (usz i = 0; i < 48; i++) {
    h48[i] = 0;
  }
  for (usz i = 0; i < n; i++) {
    h48[off + i] = hash.p[i];
  }
}

static int chv_verify_p384(wired_span key, wired_span sig, wired_span hash) {
  u8 x[48], y[48], r[48], s[48], h48[48];
  if (!x509_ec_pubkey384(key, x, y)) {
    return 0;
  }
  if (!ecdsasig_decode(sig, r, s, 48)) {
    return 0;
  }
  chv_hash_to_scalar48(hash, h48);
  return ecdsa_p384_verify(x, y, r, s, h48);
}

/* ecdsa_p521_verify takes the raw digest and keeps its leftmost 521 bits
 * (FIPS 186-4 6.4), so every allowlisted hash passes through whole. */
static int chv_verify_p521(wired_span key, wired_span sig, wired_span hash) {
  u8 x[66], y[66], r[66], s[66];
  if (!x509_ec_pubkey521(key, x, y)) {
    return 0;
  }
  if (!ecdsasig_decode(sig, r, s, 66)) {
    return 0;
  }
  return ecdsa_p521_verify(x, y, r, s, hash.p, hash.n);
}

/* One supported curve: its namedCurve test, the shortest digest whose
 * security strength meets the curve's (FIPS 186-4 6.1.1/6.4: SHA-256 for
 * P-256, SHA-384 for P-384, SHA-512 for P-521; SHA-224 meets none), and its
 * verifier. */
typedef struct {
  int (*is)(wired_span curve_oid);
  usz min_hash;
  int (*verify)(wired_span key, wired_span sig, wired_span hash);
} chv_curve;

static const chv_curve chv_curves[] = {
    {x509_is_p256, 32, chv_verify_p256},
    {x509_is_p384, 48, chv_verify_p384},
    {x509_is_p521, 64, chv_verify_p521},
};

static int chv_curve_find(wired_span curve_oid, const chv_curve** cv) {
  for (usz i = 0; i < sizeof(chv_curves) / sizeof(chv_curves[0]); i++) {
    if (chv_curves[i].is(curve_oid)) {
      *cv = &chv_curves[i];
      return 1;
    }
  }
  return 0;
}

/* RFC 5480 2.1.1: the curve is the SPKI's namedCurve. Absent, implicitCurve
 * (NULL) and specifiedCurve parameters fail x509_ec_curve. */
static int chv_curve_of(wired_span tbs, const chv_curve** cv) {
  wired_span curve;
  return x509_ec_curve(tbs, &curve) && chv_curve_find(curve, cv);
}

int castore_verify_ecdsa_issuer(
    wired_span tbs, wired_span key, wired_span sig, wired_span hash) {
  const chv_curve* cv;
  if (!chv_curve_of(tbs, &cv)) {
    return 0;
  }
  return hash.n >= cv->min_hash && cv->verify(key, sig, hash);
}
