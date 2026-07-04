#include "crypto/pki/trust/castore/chainverify.h"

#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"
#include "crypto/pki/cert/tbscert/fields.h"
#include "crypto/pki/cert/tbscert/sigalg.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/rsa_pubkey.h"
#include "crypto/pki/encoding/x509/sigalgoid.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"
#include "crypto/symmetric/hash/hash/sha512.h"

/* View issuer_cert's subjectPublicKey BIT STRING value and its algorithm OID.
 */
static int issuer_key(quic_span issuer_cert, quic_span* alg, quic_span* key) {
  quic_x509 c;
  if (!quic_x509_parse(issuer_cert, &c)) return 0;
  return quic_x509_public_key(c.tbs, alg, key);
}

/* Digest dispatch: hash kind -> length and function. */
typedef void (*chv_hash_fn)(const u8*, usz, u8*);
static const struct {
  u8          kind;
  usz         len;
  chv_hash_fn fn;
} chv_hashes[] = {
    {QUIC_X509_HASH_SHA256, 32, quic_sha256},
    {QUIC_X509_HASH_SHA384, 48, quic_sha384},
    {QUIC_X509_HASH_SHA512, 64, quic_sha512},
};

static int chv_hash_select(u8 kind, usz* hlen, chv_hash_fn* fn) {
  for (usz i = 0; i < sizeof(chv_hashes) / sizeof(chv_hashes[0]); i++)
    if (chv_hashes[i].kind == kind) {
      *hlen = chv_hashes[i].len;
      *fn   = chv_hashes[i].fn;
      return 1;
    }
  return 0;
}

/* The signed side of one certificate: its allowlisted sigAlg, the digest of
 * its tbsCertificate under that sigAlg's hash, and its raw signature. */
typedef struct {
  quic_x509_sigalg sa;
  u8               hash[64];
  usz              hash_len;
  quic_span        sig;
} chv_signed;

/* Parse the cert and require its outer sigAlg to be allowlisted. */
static int chv_sigalg(quic_span cert, quic_x509* c, quic_x509_sigalg* sa) {
  if (!quic_x509_parse(cert, c)) return 0;
  return quic_x509_sigalg_lookup(c->sig_alg_oid, sa);
}

/* RFC 5280 6.1.3. Digest cert's tbsCertificate with the hash its own
 * signatureAlgorithm names (fail closed on unlisted algorithms). */
static int tbs_hash(quic_span cert, chv_signed* sg) {
  quic_x509   c;
  chv_hash_fn fn;
  if (!chv_sigalg(cert, &c, &sg->sa)) return 0;
  if (!chv_hash_select(sg->sa.hash_kind, &sg->hash_len, &fn)) return 0;
  fn(c.tbs.p, c.tbs.n, sg->hash);
  return 1;
}

/* RFC 5280 4.1.1.3. View cert's signatureValue, dropping the BIT STRING's
 * leading unused-bits octet (0x00 for whole-octet signatures). */
static int cert_sig(quic_span cert, quic_span* sig) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  if (c.sig.n < 1) return 0;
  *sig = quic_span_of(c.sig.p + 1, c.sig.n - 1);
  return 1;
}

/* SEC1 C.5. Strip one INTEGER sign pad. */
static void chv_strip_pad(quic_span* v) {
  if (v->n > 1 && v->p[0] == 0x00) {
    v->p++;
    v->n--;
  }
}

static void chv_left_pad32(u8 out[32], quic_span v) {
  for (usz i = 0; i < 32; i++) out[i] = 0;
  for (usz i = 0; i < v.n; i++) out[32 - v.n + i] = v.p[i];
}

/* A stripped INTEGER value that fits a P-256 scalar. */
static int fits_scalar(usz len) { return len >= 1 && len <= 32; }

/* Copy one INTEGER element of c into a 32-byte big-endian field. */
static int chv_copy_int32(quic_derseq* c, u8 out[32]) {
  quic_span v;
  if (!quic_derseq_next_tagged(c, QUIC_DER_INTEGER, &v)) return 0;
  chv_strip_pad(&v);
  if (!fits_scalar(v.n)) return 0;
  chv_left_pad32(out, v);
  return 1;
}

/* SEC1 C.5. ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }. */
static int chv_ecdsa_split(quic_span sig, u8 r[32], u8 s[32]) {
  quic_span   seq;
  quic_derseq c;
  if (!quic_der_seq(sig, &seq)) return 0;
  quic_derseq_init(&c, seq);
  if (!chv_copy_int32(&c, r)) return 0;
  return chv_copy_int32(&c, s);
}

/* FIPS 186-4 6.4: a digest wider than the P-256 order uses its leftmost 32
 * bytes (a 32-byte digest is copied whole). */
static void chv_hash_to_scalar32(const u8* hash, u8 h32[32]) {
  for (usz i = 0; i < 32; i++) h32[i] = hash[i];
}

static int chv_verify_p256(quic_span key, quic_span sig, const u8* hash) {
  u8 x[32], y[32], r[32], s[32], h32[32];
  if (!quic_x509_ec_pubkey(key, x, y)) return 0;
  if (!chv_ecdsa_split(sig, r, s)) return 0;
  chv_hash_to_scalar32(hash, h32);
  return quic_ecdsa_p256_verify(x, y, r, s, h32);
}

/* A stripped INTEGER value that fits a P-384 scalar. */
static int fits_scalar48(usz len) { return len >= 1 && len <= 48; }

static void chv_left_pad48(u8 out[48], quic_span v) {
  for (usz i = 0; i < 48; i++) out[i] = 0;
  for (usz i = 0; i < v.n; i++) out[48 - v.n + i] = v.p[i];
}

/* Copy one INTEGER element of c into a 48-byte big-endian field. */
static int chv_copy_int48(quic_derseq* c, u8 out[48]) {
  quic_span v;
  if (!quic_derseq_next_tagged(c, QUIC_DER_INTEGER, &v)) return 0;
  chv_strip_pad(&v);
  if (!fits_scalar48(v.n)) return 0;
  chv_left_pad48(out, v);
  return 1;
}

/* SEC1 C.5. ECDSA-Sig-Value with 48-byte scalars (P-384). */
static int chv_ecdsa_split48(quic_span sig, u8 r[48], u8 s[48]) {
  quic_span   seq;
  quic_derseq c;
  if (!quic_der_seq(sig, &seq)) return 0;
  quic_derseq_init(&c, seq);
  if (!chv_copy_int48(&c, r)) return 0;
  return chv_copy_int48(&c, s);
}

/* FIPS 186-4 6.4: left-zero-extend the digest into 48 bytes (a 48-byte digest
 * is copied whole), matching the P-384 order size. */
static void chv_hash_to_scalar48(quic_span hash, u8 h48[48]) {
  usz off = 48 - hash.n;
  for (usz i = 0; i < 48; i++) h48[i] = 0;
  for (usz i = 0; i < hash.n; i++) h48[off + i] = hash.p[i];
}

static int chv_verify_p384(quic_span key, quic_span sig, quic_span hash) {
  u8 x[48], y[48], r[48], s[48], h48[48];
  if (!quic_x509_ec_pubkey384(key, x, y)) return 0;
  if (!chv_ecdsa_split48(sig, r, s)) return 0;
  chv_hash_to_scalar48(hash, h48);
  return quic_ecdsa_p384_verify(x, y, r, s, h48);
}

/* The SPKI BIT STRING length selects the curve: 66 bytes P-256, 98 P-384. */
static int chv_verify_ecdsa(quic_span key, quic_span sig, quic_span hash) {
  if (key.n == 98) return chv_verify_p384(key, sig, hash);
  return chv_verify_p256(key, sig, hash.p);
}

static int chv_verify_rsa(quic_span key, quic_span sig, quic_span hash) {
  quic_span n, e;
  if (!quic_x509_rsa_pubkey(key, &n, &e)) return 0;
  quic_rsa_pub pub = {n, e};
  return quic_rsa_pkcs1_verify(&pub, sig, hash);
}

/* The issuer SPKI must be an EC key when the sigAlg says ECDSA. */
static int verify_ecdsa_key(
    const chv_signed* sg, quic_span alg, quic_span key) {
  return quic_x509_is_ec(alg) &&
         chv_verify_ecdsa(key, sg->sig, quic_span_of(sg->hash, sg->hash_len));
}

/* The issuer SPKI must be an RSA key when the sigAlg says PKCS#1. */
static int verify_rsa_key(const chv_signed* sg, quic_span alg, quic_span key) {
  return quic_x509_is_rsa(alg) &&
         chv_verify_rsa(key, sg->sig, quic_span_of(sg->hash, sg->hash_len));
}

/* RFC 5280 6.1.3. Dispatch on the sigAlg's key kind, cross-checked against
 * the issuer's actual SPKI key type. */
static int verify_by_key(const chv_signed* sg, quic_span alg, quic_span key) {
  if (sg->sa.key_kind == QUIC_X509_SIG_ECDSA)
    return verify_ecdsa_key(sg, alg, key);
  return verify_rsa_key(sg, alg, key);
}

/* RFC 5280 4.1.1.2. The inner tbsCertificate.signatureAlgorithm OID must equal
 * the outer signatureAlgorithm OID, or the certificate is malformed. */
static int sigalg_consistent(quic_span cert) {
  quic_x509    c;
  quic_tbscert t;
  if (!quic_x509_parse(cert, &c)) return 0;
  if (!quic_tbscert_parse(c.tbs, &t)) return 0;
  return quic_tbscert_sigalg_matches(&t, c.sig_alg_oid);
}

/* The signed bytes of cert: consistent sig algs, its tbs hash under the
 * sigAlg's digest, and its raw signature. */
static int cert_signed(quic_span cert, chv_signed* sg) {
  if (!sigalg_consistent(cert)) return 0;
  if (!tbs_hash(cert, sg)) return 0;
  return cert_sig(cert, &sg->sig);
}

int quic_castore_verify_signed_by(quic_span cert, quic_span issuer_cert) {
  quic_span  alg, key;
  chv_signed sg;
  if (!issuer_key(issuer_cert, &alg, &key)) return 0;
  if (!cert_signed(cert, &sg)) return 0;
  return verify_by_key(&sg, alg, key);
}
