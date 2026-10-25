#include "crypto/pki/trust/castore/chainverify.h"

#include "common/bytes/util/num.h"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p521/ecdsa_verify.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"
#include "crypto/pki/cert/tbscert/fields.h"
#include "crypto/pki/cert/tbscert/sigalg.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/rsa_pubkey.h"
#include "crypto/pki/encoding/x509/sigalgoid.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"
#include "crypto/symmetric/hash/hash/sha512.h"

/* The issuer's tbsCertificate (for its SPKI parameters), SPKI algorithm OID
 * and subjectPublicKey BIT STRING value. */
typedef struct {
  wired_span tbs, alg, key;
} chv_issuer;

static int issuer_key(wired_span issuer_cert, chv_issuer* is) {
  x509 c;
  if (!x509_parse(issuer_cert, &c)) {
    return 0;
  }
  is->tbs = c.tbs;
  return x509_public_key(c.tbs, &is->alg, &is->key);
}

/* Digest dispatch: hash kind -> length and function. */
typedef void (*chv_hash_fn)(const u8*, usz, u8*);
static const struct {
  u8          kind;
  usz         len;
  chv_hash_fn fn;
} chv_hashes[] = {
    {X509_HASH_SHA256, 32, wired_sha256},
    {X509_HASH_SHA384, 48, sha384},
    {X509_HASH_SHA512, 64, sha512},
};

static int chv_hash_select(u8 kind, usz* hlen, chv_hash_fn* fn) {
  for (usz i = 0; i < sizeof(chv_hashes) / sizeof(chv_hashes[0]); i++) {
    if (chv_hashes[i].kind == kind) {
      *hlen = chv_hashes[i].len;
      *fn   = chv_hashes[i].fn;
      return 1;
    }
  }
  return 0;
}

/* The signed side of one certificate: its allowlisted sigAlg, the digest of
 * its tbsCertificate under that sigAlg's hash, and its raw signature. */
typedef struct {
  x509_sigalg sa;
  u8          hash[64];
  usz         hash_len;
  wired_span  sig;
} chv_signed;

/* Parse the cert and require its outer sigAlg to be allowlisted. */
static int chv_sigalg(wired_span cert, x509* c, x509_sigalg* sa) {
  if (!x509_parse(cert, c)) {
    return 0;
  }
  return x509_sigalg_lookup(c->sig_alg_oid, sa);
}

/* RFC 5280 6.1.3. Digest cert's tbsCertificate with the hash its own
 * signatureAlgorithm names (fail closed on unlisted algorithms). */
static int tbs_hash(wired_span cert, chv_signed* sg) {
  x509        c;
  chv_hash_fn fn;
  if (!chv_sigalg(cert, &c, &sg->sa)) {
    return 0;
  }
  if (!chv_hash_select(sg->sa.hash_kind, &sg->hash_len, &fn)) {
    return 0;
  }
  fn(c.tbs.p, c.tbs.n, sg->hash);
  return 1;
}

/* RFC 5280 4.1.1.3. View cert's signatureValue, dropping the BIT STRING's
 * leading unused-bits octet (0x00 for whole-octet signatures). */
static int cert_sig(wired_span cert, wired_span* sig) {
  x509 c;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  if (c.sig.n < 1) {
    return 0;
  }
  *sig = wired_span_of(c.sig.p + 1, c.sig.n - 1);
  return 1;
}

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
static int chv_curve_of(const chv_issuer* is, const chv_curve** cv) {
  wired_span curve;
  return x509_ec_curve(is->tbs, &curve) && chv_curve_find(curve, cv);
}

static int chv_verify_ecdsa(
    const chv_issuer* is, wired_span sig, wired_span hash) {
  const chv_curve* cv;
  if (!chv_curve_of(is, &cv)) {
    return 0;
  }
  return hash.n >= cv->min_hash && cv->verify(is->key, sig, hash);
}

static int chv_verify_rsa(wired_span key, wired_span sig, wired_span hash) {
  wired_span n, e;
  if (!x509_rsa_pubkey(key, &n, &e)) {
    return 0;
  }
  rsa_pub pub = {n, e};
  return rsa_pkcs1_verify(&pub, sig, hash);
}

/* The issuer SPKI must be an EC key when the sigAlg says ECDSA. */
static int verify_ecdsa_key(const chv_signed* sg, const chv_issuer* is) {
  return x509_is_ec(is->alg) &&
         chv_verify_ecdsa(is, sg->sig, wired_span_of(sg->hash, sg->hash_len));
}

/* The issuer SPKI must be an RSA key when the sigAlg says PKCS#1. */
static int verify_rsa_key(const chv_signed* sg, const chv_issuer* is) {
  return x509_is_rsa(is->alg) &&
         chv_verify_rsa(
             is->key, sg->sig, wired_span_of(sg->hash, sg->hash_len));
}

/* RFC 5280 6.1.3. Dispatch on the sigAlg's key kind, cross-checked against
 * the issuer's actual SPKI key type. */
static int verify_by_key(const chv_signed* sg, const chv_issuer* is) {
  if (sg->sa.key_kind == X509_SIG_ECDSA) {
    return verify_ecdsa_key(sg, is);
  }
  return verify_rsa_key(sg, is);
}

/* RFC 5280 4.1.1.2. The inner tbsCertificate.signatureAlgorithm OID must equal
 * the outer signatureAlgorithm OID, or the certificate is malformed. */
static int sigalg_consistent(wired_span cert) {
  x509    c;
  tbscert t;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  if (!tbscert_parse(c.tbs, &t)) {
    return 0;
  }
  return tbscert_sigalg_matches(&t, c.sig_alg_oid);
}

/* The signed bytes of cert: consistent sig algs, its tbs hash under the
 * sigAlg's digest, and its raw signature. */
static int cert_signed(wired_span cert, chv_signed* sg) {
  if (!sigalg_consistent(cert)) {
    return 0;
  }
  if (!tbs_hash(cert, sg)) {
    return 0;
  }
  return cert_sig(cert, &sg->sig);
}

int castore_verify_signed_by(wired_span cert, wired_span issuer_cert) {
  chv_issuer is;
  chv_signed sg;
  if (!issuer_key(issuer_cert, &is)) {
    return 0;
  }
  if (!cert_signed(cert, &sg)) {
    return 0;
  }
  return verify_by_key(&sg, &is);
}
