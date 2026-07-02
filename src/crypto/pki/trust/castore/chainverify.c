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
static int issuer_key(
    const u8  *issuer_cert,
    usz        issuer_len,
    const u8 **alg,
    usz       *alg_len,
    const u8 **key,
    usz       *key_len) {
  quic_x509 c;
  if (!quic_x509_parse(issuer_cert, issuer_len, &c)) return 0;
  return quic_x509_public_key(c.tbs, c.tbs_len, alg, alg_len, key, key_len);
}

/* Digest dispatch: hash kind -> length and function. */
typedef void (*chv_hash_fn)(const u8 *, usz, u8 *);
static const struct {
  u8          kind;
  usz         len;
  chv_hash_fn fn;
} chv_hashes[] = {
    {QUIC_X509_HASH_SHA256, 32, quic_sha256},
    {QUIC_X509_HASH_SHA384, 48, quic_sha384},
    {QUIC_X509_HASH_SHA512, 64, quic_sha512},
};

static int chv_hash_select(u8 kind, usz *hlen, chv_hash_fn *fn) {
  for (usz i = 0; i < sizeof(chv_hashes) / sizeof(chv_hashes[0]); i++)
    if (chv_hashes[i].kind == kind) {
      *hlen = chv_hashes[i].len;
      *fn   = chv_hashes[i].fn;
      return 1;
    }
  return 0;
}

/* Parse the cert and require its outer sigAlg to be allowlisted. */
static int chv_sigalg(
    const u8 *cert, usz cert_len, quic_x509 *c, quic_x509_sigalg *sa) {
  if (!quic_x509_parse(cert, cert_len, c)) return 0;
  return quic_x509_sigalg_lookup(c->sig_alg_oid, c->sig_alg_len, sa);
}

/* RFC 5280 6.1.3. Digest cert's tbsCertificate with the hash its own
 * signatureAlgorithm names (fail closed on unlisted algorithms). */
static int tbs_hash(
    const u8         *cert,
    usz               cert_len,
    quic_x509_sigalg *sa,
    u8                hash[64],
    usz              *hash_len) {
  quic_x509   c;
  chv_hash_fn fn;
  if (!chv_sigalg(cert, cert_len, &c, sa)) return 0;
  if (!chv_hash_select(sa->hash_kind, hash_len, &fn)) return 0;
  fn(c.tbs, c.tbs_len, hash);
  return 1;
}

/* RFC 5280 4.1.1.3. View cert's signatureValue, dropping the BIT STRING's
 * leading unused-bits octet (0x00 for whole-octet signatures). */
static int cert_sig(
    const u8 *cert, usz cert_len, const u8 **sig, usz *sig_len) {
  quic_x509 c;
  if (!quic_x509_parse(cert, cert_len, &c)) return 0;
  if (c.sig_len < 1) return 0;
  *sig     = c.sig + 1;
  *sig_len = c.sig_len - 1;
  return 1;
}

/* SEC1 C.5. Strip one INTEGER sign pad. */
static void chv_strip_pad(const u8 **v, usz *len) {
  if (*len > 1 && (*v)[0] == 0x00) {
    (*v)++;
    (*len)--;
  }
}

static void chv_left_pad32(u8 out[32], const u8 *v, usz len) {
  for (usz i = 0; i < 32; i++) out[i] = 0;
  for (usz i = 0; i < len; i++) out[32 - len + i] = v[i];
}

/* A stripped INTEGER value that fits a P-256 scalar. */
static int fits_scalar(usz len) { return len >= 1 && len <= 32; }

/* Read the next element of c, requiring INTEGER. */
static int chv_next_int(quic_derseq *c, const u8 **v, usz *len) {
  u8 tag;
  if (!quic_derseq_next(c, &tag, v, len)) return 0;
  return tag == QUIC_DER_INTEGER;
}

/* Copy one INTEGER element of c into a 32-byte big-endian field. */
static int chv_copy_int32(quic_derseq *c, u8 out[32]) {
  const u8 *v;
  usz       len;
  if (!chv_next_int(c, &v, &len)) return 0;
  chv_strip_pad(&v, &len);
  if (!fits_scalar(len)) return 0;
  chv_left_pad32(out, v, len);
  return 1;
}

/* View an outer SEQUENCE value. */
static int chv_read_seq(const u8 *buf, usz n, const u8 **val, usz *vlen) {
  u8  tag;
  usz used;
  if (!quic_der_read(buf, n, &tag, val, vlen, &used)) return 0;
  return tag == QUIC_DER_SEQUENCE;
}

/* SEC1 C.5. ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }. */
static int chv_ecdsa_split(const u8 *sig, usz sig_len, u8 r[32], u8 s[32]) {
  const u8   *seq;
  usz         seq_len;
  quic_derseq c;
  if (!chv_read_seq(sig, sig_len, &seq, &seq_len)) return 0;
  quic_derseq_init(&c, seq, seq_len);
  if (!chv_copy_int32(&c, r)) return 0;
  return chv_copy_int32(&c, s);
}

/* FIPS 186-4 6.4: a digest wider than the P-256 order uses its leftmost 32
 * bytes (a 32-byte digest is copied whole). */
static void chv_hash_to_scalar32(const u8 *hash, u8 h32[32]) {
  for (usz i = 0; i < 32; i++) h32[i] = hash[i];
}

static int chv_verify_p256(
    const u8 *key, usz key_len, const u8 *sig, usz sig_len, const u8 *hash) {
  u8 x[32], y[32], r[32], s[32], h32[32];
  if (!quic_x509_ec_pubkey(key, key_len, x, y)) return 0;
  if (!chv_ecdsa_split(sig, sig_len, r, s)) return 0;
  chv_hash_to_scalar32(hash, h32);
  return quic_ecdsa_p256_verify(x, y, r, s, h32);
}

/* A stripped INTEGER value that fits a P-384 scalar. */
static int fits_scalar48(usz len) { return len >= 1 && len <= 48; }

static void chv_left_pad48(u8 out[48], const u8 *v, usz len) {
  for (usz i = 0; i < 48; i++) out[i] = 0;
  for (usz i = 0; i < len; i++) out[48 - len + i] = v[i];
}

/* Copy one INTEGER element of c into a 48-byte big-endian field. */
static int chv_copy_int48(quic_derseq *c, u8 out[48]) {
  const u8 *v;
  usz       len;
  if (!chv_next_int(c, &v, &len)) return 0;
  chv_strip_pad(&v, &len);
  if (!fits_scalar48(len)) return 0;
  chv_left_pad48(out, v, len);
  return 1;
}

/* SEC1 C.5. ECDSA-Sig-Value with 48-byte scalars (P-384). */
static int chv_ecdsa_split48(const u8 *sig, usz sig_len, u8 r[48], u8 s[48]) {
  const u8   *seq;
  usz         seq_len;
  quic_derseq c;
  if (!chv_read_seq(sig, sig_len, &seq, &seq_len)) return 0;
  quic_derseq_init(&c, seq, seq_len);
  if (!chv_copy_int48(&c, r)) return 0;
  return chv_copy_int48(&c, s);
}

/* FIPS 186-4 6.4: left-zero-extend the digest into 48 bytes (a 48-byte digest
 * is copied whole), matching the P-384 order size. */
static void chv_hash_to_scalar48(const u8 *hash, usz hash_len, u8 h48[48]) {
  usz off = 48 - hash_len;
  for (usz i = 0; i < 48; i++) h48[i] = 0;
  for (usz i = 0; i < hash_len; i++) h48[off + i] = hash[i];
}

static int chv_verify_p384(
    const u8 *key,
    usz       key_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *hash,
    usz       hash_len) {
  u8 x[48], y[48], r[48], s[48], h48[48];
  if (!quic_x509_ec_pubkey384(key, key_len, x, y)) return 0;
  if (!chv_ecdsa_split48(sig, sig_len, r, s)) return 0;
  chv_hash_to_scalar48(hash, hash_len, h48);
  return quic_ecdsa_p384_verify(x, y, r, s, h48);
}

/* The SPKI BIT STRING length selects the curve: 66 bytes P-256, 98 P-384. */
static int chv_verify_ecdsa(
    const u8 *key,
    usz       key_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *hash,
    usz       hash_len) {
  if (key_len == 98)
    return chv_verify_p384(key, key_len, sig, sig_len, hash, hash_len);
  return chv_verify_p256(key, key_len, sig, sig_len, hash);
}

static int chv_verify_rsa(
    const u8 *key,
    usz       key_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *hash,
    usz       hash_len) {
  const u8 *n, *e;
  usz       n_len, e_len;
  if (!quic_x509_rsa_pubkey(key, key_len, &n, &n_len, &e, &e_len)) return 0;
  return quic_rsa_pkcs1_verify(
      n, n_len, e, e_len, sig, sig_len, hash, hash_len);
}

/* The issuer SPKI must be an EC key when the sigAlg says ECDSA. */
static int verify_ecdsa_key(
    const u8 *alg,
    usz       alg_len,
    const u8 *key,
    usz       key_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *hash,
    usz       hash_len) {
  return quic_x509_is_ec(alg, alg_len) &&
         chv_verify_ecdsa(key, key_len, sig, sig_len, hash, hash_len);
}

/* The issuer SPKI must be an RSA key when the sigAlg says PKCS#1. */
static int verify_rsa_key(
    const u8 *alg,
    usz       alg_len,
    const u8 *key,
    usz       key_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *hash,
    usz       hash_len) {
  return quic_x509_is_rsa(alg, alg_len) &&
         chv_verify_rsa(key, key_len, sig, sig_len, hash, hash_len);
}

/* RFC 5280 6.1.3. Dispatch on the sigAlg's key kind, cross-checked against
 * the issuer's actual SPKI key type. */
static int verify_by_key(
    const quic_x509_sigalg *sa,
    const u8               *alg,
    usz                     alg_len,
    const u8               *key,
    usz                     key_len,
    const u8               *sig,
    usz                     sig_len,
    const u8               *hash,
    usz                     hash_len) {
  if (sa->key_kind == QUIC_X509_SIG_ECDSA)
    return verify_ecdsa_key(
        alg, alg_len, key, key_len, sig, sig_len, hash, hash_len);
  return verify_rsa_key(
      alg, alg_len, key, key_len, sig, sig_len, hash, hash_len);
}

/* RFC 5280 4.1.1.2. The inner tbsCertificate.signatureAlgorithm OID must equal
 * the outer signatureAlgorithm OID, or the certificate is malformed. */
static int sigalg_consistent(const u8 *cert, usz cert_len) {
  quic_x509    c;
  quic_tbscert t;
  if (!quic_x509_parse(cert, cert_len, &c)) return 0;
  if (!quic_tbscert_parse(c.tbs, c.tbs_len, &t)) return 0;
  return quic_tbscert_sigalg_matches(&t, c.sig_alg_oid, c.sig_alg_len);
}

/* The signed bytes of cert: consistent sig algs, its tbs hash under the
 * sigAlg's digest, and its raw signature. */
static int cert_signed(
    const u8         *cert,
    usz               cert_len,
    quic_x509_sigalg *sa,
    u8                hash[64],
    usz              *hash_len,
    const u8        **sig,
    usz              *sig_len) {
  if (!sigalg_consistent(cert, cert_len)) return 0;
  if (!tbs_hash(cert, cert_len, sa, hash, hash_len)) return 0;
  return cert_sig(cert, cert_len, sig, sig_len);
}

int quic_castore_verify_signed_by(
    const u8 *cert, usz cert_len, const u8 *issuer_cert, usz issuer_len) {
  const u8        *alg, *key, *sig;
  usz              alg_len, key_len, sig_len, hash_len;
  u8               hash[64];
  quic_x509_sigalg sa;
  if (!issuer_key(issuer_cert, issuer_len, &alg, &alg_len, &key, &key_len))
    return 0;
  if (!cert_signed(cert, cert_len, &sa, hash, &hash_len, &sig, &sig_len))
    return 0;
  return verify_by_key(
      &sa, alg, alg_len, key, key_len, sig, sig_len, hash, hash_len);
}
