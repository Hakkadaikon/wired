#include "crypto/pki/trust/castore/chainverify.h"

#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/asymmetric/rsa/rsa_pss_verify.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"
#include "crypto/pki/cert/tbscert/fields.h"
#include "crypto/pki/cert/tbscert/sigalg.h"
#include "crypto/pki/encoding/x509/rsa_pubkey.h"
#include "crypto/pki/encoding/x509/sigalgoid.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/chainverify_impl.h"
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

/* RFC 8410 6: Ed25519 signs the tbsCertificate itself, so there is no
 * digest to compute. */
static void chv_hash_none(const u8* in, usz n, u8* out) {
  (void)in;
  (void)n;
  (void)out;
}
static const struct {
  u8          kind;
  usz         len;
  chv_hash_fn fn;
} chv_hashes[] = {
    {X509_HASH_SHA256, 32, wired_sha256},
    {X509_HASH_SHA384, 48, sha384},
    {X509_HASH_SHA512, 64, sha512},
    {X509_HASH_NONE, 0, chv_hash_none},
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

/* The signed side of one certificate: its allowlisted sigAlg, its
 * tbsCertificate and the digest of that under the sigAlg's hash, and its raw
 * signature. */
typedef struct {
  x509_sigalg sa;
  wired_span  tbs;
  u8          hash[64];
  usz         hash_len;
  chv_hash_fn hash_fn; /* the digest behind hash (RSASSA-PSS reuses it) */
  wired_span  sig;
} chv_signed;

/* RFC 5280 6.1.3. Digest c's tbsCertificate with the hash its own
 * signatureAlgorithm names (fail closed on unlisted algorithms). */
static int tbs_hash(const x509* c, chv_signed* sg) {
  chv_hash_fn fn;
  if (!x509_sigalg_lookup(c->sig_alg_oid, c->sig_alg_params, &sg->sa)) {
    return 0;
  }
  if (!chv_hash_select(sg->sa.hash_kind, &sg->hash_len, &fn)) {
    return 0;
  }
  sg->tbs     = c->tbs;
  sg->hash_fn = fn;
  fn(c->tbs.p, c->tbs.n, sg->hash);
  return 1;
}

/* RFC 5280 4.1.1.3. View c's signatureValue, dropping the BIT STRING's
 * leading unused-bits octet (0x00 for whole-octet signatures). */
static int cert_sig(const x509* c, wired_span* sig) {
  if (c->sig.n < 1) {
    return 0;
  }
  *sig = wired_span_of(c->sig.p + 1, c->sig.n - 1);
  return 1;
}

static int chv_verify_ecdsa(
    const chv_issuer* is, wired_span sig, wired_span hash) {
  return castore_verify_ecdsa_issuer(is->tbs, is->key, sig, hash);
}

static int chv_verify_rsa(wired_span key, wired_span sig, wired_span hash) {
  wired_span n, e;
  if (!x509_rsa_pubkey(key, &n, &e)) {
    return 0;
  }
  rsa_pub pub = {n, e};
  return rsa_pkcs1_verify(&pub, sig, hash);
}

/* RFC 4055 3.1 / RFC 8017 8.1.2: the allowlist admits RSASSA-PSS only with
 * MGF1 over the message hash and saltLength = hLen. */
static int chv_verify_pss(wired_span key, const chv_signed* sg) {
  wired_span  n, e;
  rsa_pss_cfg cfg = {{sg->hash_fn, sg->hash_len}, sg->hash_len};
  if (!x509_rsa_pubkey(key, &n, &e)) {
    return 0;
  }
  rsa_pub pub = {n, e};
  return rsa_pss_verify_cfg(
      &pub, sg->sig, wired_span_of(sg->hash, sg->hash_len), &cfg);
}

/* RFC 8446 4.2.3 rsa_pss_rsae_*: the issuer SPKI must be rsaEncryption.
 * shortcut: an id-RSASSA-PSS SPKI (rsa_pss_pss_*, RFC 4055 3.3) is
 * rejected; accept it, with its parameter constraints, if a CA needs it. */
static int verify_pss_key(const chv_signed* sg, const chv_issuer* is) {
  return x509_is_rsa(is->alg) && chv_verify_pss(is->key, sg);
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

/* RFC 8410 4: the issuer's subjectPublicKey is the 32-byte key behind the
 * BIT STRING's unused-bits octet; the signature is 64 bytes (RFC 8032). */
static int chv_ed25519_shape(const chv_signed* sg, const chv_issuer* is) {
  return is->key.n == ED25519_PUBKEY + 1 && is->key.p[0] == 0x00 &&
         sg->sig.n == ED25519_SIG;
}

/* RFC 8410 6. The issuer SPKI must be id-Ed25519 when the sigAlg is; the
 * signature is checked over the tbsCertificate DER itself. */
static int verify_ed25519_key(const chv_signed* sg, const chv_issuer* is) {
  return x509_is_ed25519(is->alg) && chv_ed25519_shape(sg, is) &&
         ed25519_verify(sg->sig.p, sg->tbs.p, sg->tbs.n, is->key.p + 1);
}

/* RFC 5280 6.1.3. Dispatch on the sigAlg's key kind (every X509_SIG_* the
 * allowlist can return), each cross-checked against the issuer's actual
 * SPKI key type. */
typedef int (*chv_verify_fn)(const chv_signed*, const chv_issuer*);
static const chv_verify_fn chv_verifiers[] = {
    [X509_SIG_ECDSA]     = verify_ecdsa_key,
    [X509_SIG_RSA_PKCS1] = verify_rsa_key,
    [X509_SIG_ED25519]   = verify_ed25519_key,
    [X509_SIG_RSA_PSS]   = verify_pss_key,
};

static int verify_by_key(const chv_signed* sg, const chv_issuer* is) {
  return chv_verifiers[sg->sa.key_kind](sg, is);
}

/* RFC 5280 4.1.1.2. The inner tbsCertificate.signatureAlgorithm must equal
 * the outer signatureAlgorithm -- OID and parameters -- or the certificate
 * is malformed. */
static int sigalg_consistent(const x509* c) {
  tbscert t;
  if (!tbscert_parse(c->tbs, &t)) {
    return 0;
  }
  return tbscert_sigalg_matches(&t, c->sig_alg_oid, c->sig_alg_params);
}

/* The signed bytes of parsed c: consistent sig algs, its tbs hash under the
 * sigAlg's digest, and its raw signature. */
static int parsed_signed(const x509* c, chv_signed* sg) {
  if (!sigalg_consistent(c)) {
    return 0;
  }
  if (!tbs_hash(c, sg)) {
    return 0;
  }
  return cert_sig(c, &sg->sig);
}

/* Parse cert once and view its signed bytes. */
static int cert_signed(wired_span cert, chv_signed* sg) {
  x509 c;
  if (!x509_parse(cert, &c)) {
    return 0;
  }
  return parsed_signed(&c, sg);
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
