#include "tls/handshake/core/tls/certverify.h"

#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/rsa/rsa_pss_verify.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/rsa_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* RFC 8446 4.4.3. The signed content: 64*0x20, the context string, a 0x00
 * separator, then the 32-byte transcript hash. */
static const char cv_ctx_str[] = "TLS 1.3, server CertificateVerify";

static void fill_pad(u8 out[64]) {
  for (usz i = 0; i < 64; i++) out[i] = 0x20;
}

static void put_ctx(u8 *out) {
  for (usz i = 0; i < 33; i++) out[i] = (u8)cv_ctx_str[i];
}

static void put_hash(u8 *out, const u8 transcript_hash[32]) {
  for (usz i = 0; i < 32; i++) out[i] = transcript_hash[i];
}

static void cv_build_signed(const u8 transcript_hash[32], u8 out[130]) {
  fill_pad(out);
  put_ctx(out + 64);
  out[97] = 0x00;
  put_hash(out + 98, transcript_hash);
}

/* View the end-entity certificate's subjectPublicKey BIT STRING value. */
static int cert_spki_key(
    const u8 *cert, usz cert_len, const u8 **key, usz *key_len) {
  quic_x509 c;
  quic_span oid, k;
  if (!quic_x509_parse(quic_span_of(cert, cert_len), &c)) return 0;
  if (!quic_x509_public_key(c.tbs, &oid, &k)) return 0;
  *key     = k.p;
  *key_len = k.n;
  return 1;
}

/* SEC1 C.5. Strip a single INTEGER sign pad. */
static void cv_strip_pad(const u8 **v, usz *len) {
  if (*len > 1 && (*v)[0] == 0x00) {
    (*v)++;
    (*len)--;
  }
}

static void left_pad32(u8 out[32], const u8 *v, usz len) {
  for (usz i = 0; i < 32; i++) out[i] = 0;
  for (usz i = 0; i < len; i++) out[32 - len + i] = v[i];
}

/* Read the next element of c, requiring tag want. */
static int cv_next_tag(quic_derseq *c, u8 want, const u8 **v, usz *len) {
  quic_span s;
  if (!quic_derseq_next_tagged(c, want, &s)) return 0;
  *v   = s.p;
  *len = s.n;
  return 1;
}

/* A field of 1..32 octets fits a P-256 scalar. */
static int fits32(usz len) { return len >= 1 && len <= 32; }

/* Copy one INTEGER into a 32-byte big-endian field (rejecting > 32 octets). */
static int copy_int32(quic_derseq *c, u8 out[32]) {
  const u8 *v;
  usz       len;
  if (!cv_next_tag(c, QUIC_DER_INTEGER, &v, &len)) return 0;
  cv_strip_pad(&v, &len);
  if (!fits32(len)) return 0;
  left_pad32(out, v, len);
  return 1;
}

/* SEC1 C.5. ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }. */
static int ecdsa_split(const u8 *sig, usz sig_len, u8 r[32], u8 s[32]) {
  quic_derseq c;
  quic_span   seq;
  if (!quic_der_seq(quic_span_of(sig, sig_len), &seq)) return 0;
  quic_derseq_init(&c, seq);
  if (!copy_int32(&c, r)) return 0;
  return copy_int32(&c, s);
}

/* Pull the EC point and the (r, s) signature. */
static int ecdsa_inputs(
    const u8 *cert,
    usz       cert_len,
    const u8 *sig,
    usz       sig_len,
    u8        x[32],
    u8        y[32],
    u8        r[32],
    u8        s[32]) {
  const u8 *key;
  usz       key_len;
  if (!cert_spki_key(cert, cert_len, &key, &key_len)) return 0;
  if (!quic_x509_ec_pubkey(quic_span_of(key, key_len), x, y)) return 0;
  return ecdsa_split(sig, sig_len, r, s);
}

static int verify_ecdsa(
    const u8 *cert,
    usz       cert_len,
    const u8 *sig,
    usz       sig_len,
    const u8  hash[32]) {
  u8 x[32], y[32], r[32], s[32];
  if (!ecdsa_inputs(cert, cert_len, sig, sig_len, x, y, r, s)) return 0;
  return quic_ecdsa_p256_verify(x, y, r, s, hash);
}

static int verify_rsa(
    const u8 *cert,
    usz       cert_len,
    const u8 *sig,
    usz       sig_len,
    const u8  hash[32]) {
  const u8 *key;
  usz       key_len;
  quic_span n, e;
  if (!cert_spki_key(cert, cert_len, &key, &key_len)) return 0;
  if (!quic_x509_rsa_pubkey(quic_span_of(key, key_len), &n, &e)) return 0;
  /* RFC 8446 9.1: rsa_pss_rsae_sha256 is RSASSA-PSS (never PKCS#1 v1.5). */
  quic_rsa_pub pub = {n, e};
  return quic_rsa_pss_verify(
      &pub, (quic_span){sig, sig_len}, (quic_span){hash, 32});
}

/* RFC 5280 4.1.2.7: a 32-byte raw key wrapped in the BIT STRING's leading
 * unused-bits octet (0x00). */
static int is_ed25519_bits(const u8 *bits, usz len) {
  return len == QUIC_ED25519_PUBKEY + 1 && bits[0] == 0x00;
}

/* The 32-byte Ed25519 public key from the certificate, past the unused-bits
 * octet. */
static int ed25519_key(const u8 *cert, usz cert_len, const u8 **key) {
  const u8 *bits;
  usz       key_len;
  if (!cert_spki_key(cert, cert_len, &bits, &key_len)) return 0;
  if (!is_ed25519_bits(bits, key_len)) return 0;
  *key = bits + 1;
  return 1;
}

static int verify_ed25519(
    const u8 *cert,
    usz       cert_len,
    const u8 *sig,
    usz       sig_len,
    const u8  content[130]) {
  const u8 *key;
  if (sig_len != QUIC_ED25519_SIG) return 0;
  if (!ed25519_key(cert, cert_len, &key)) return 0;
  return quic_ed25519_verify(sig, content, 130, key);
}

/* RFC 8446 4.4.3. Hash branches (ecdsa/rsa over SHA-256 of the content). */
static int verify_hashed(
    u16       scheme,
    const u8 *cert,
    usz       cert_len,
    const u8 *sig,
    usz       sig_len,
    const u8  content[130]) {
  u8 hash[32];
  quic_sha256(content, 130, hash);
  if (scheme == QUIC_TLS_SCHEME_ECDSA_P256)
    return verify_ecdsa(cert, cert_len, sig, sig_len, hash);
  if (scheme == QUIC_TLS_SCHEME_RSA_PSS_SHA256)
    return verify_rsa(cert, cert_len, sig, sig_len, hash);
  return 0;
}

int quic_tls_verify_cert_signature(
    u16       scheme,
    const u8 *cert,
    usz       cert_len,
    const u8 *sig,
    usz       sig_len,
    const u8  transcript_hash[32]) {
  u8 content[130];
  cv_build_signed(transcript_hash, content);
  if (scheme == QUIC_TLS_SCHEME_ED25519)
    return verify_ed25519(cert, cert_len, sig, sig_len, content);
  return verify_hashed(scheme, cert, cert_len, sig, sig_len, content);
}
