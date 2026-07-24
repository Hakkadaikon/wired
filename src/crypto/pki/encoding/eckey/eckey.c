#include "crypto/pki/encoding/eckey/eckey.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* Open the outer SEQUENCE and read the leading version INTEGER. */
static int eckey_open(quic_span der, quic_derseq* c, u64* v) {
  quic_span body, iv;
  if (!quic_der_seq(der, &body)) return 0;
  quic_derseq_init(c, body);
  return quic_derseq_next_tagged(c, QUIC_DER_INTEGER, &iv) &&
         quic_der_uint(iv.p, iv.n, v);
}

/* RFC 5915 3. privateKey OCTET STRING: exactly the 32-byte scalar. */
static int eckey_scalar(quic_derseq* c, u8 out[32]) {
  quic_span priv;
  if (!quic_derseq_next_tagged(c, QUIC_DER_OCTET_STRING, &priv)) return 0;
  if (priv.n != 32) return 0;
  quic_memcpy(out, priv.p, 32);
  return 1;
}

/* RFC 5915 3. SEC1 rest after the version: version must be 1. */
static int eckey_sec1_at(quic_derseq* c, u64 v, u8 out[32]) {
  if (v != 1) return 0;
  return eckey_scalar(c, out);
}

/* RFC 5958 2. Skip AlgorithmIdentifier, view the privateKey octets. */
static int eckey_pkcs8_unwrap(quic_derseq* c, quic_span* inner) {
  quic_span alg;
  return quic_derseq_next_tagged(c, QUIC_DER_SEQUENCE, &alg) &&
         quic_derseq_next_tagged(c, QUIC_DER_OCTET_STRING, inner);
}

/* RFC 5958 2. The privateKey octets hold a SEC1 ECPrivateKey. */
static int eckey_pkcs8_at(quic_derseq* c, u8 out[32]) {
  quic_span   inner;
  quic_derseq ic;
  u64         iv;
  if (!eckey_pkcs8_unwrap(c, &inner)) return 0;
  if (!eckey_open(inner, &ic, &iv)) return 0;
  return eckey_sec1_at(&ic, iv, out);
}

/* Version 0 is PKCS#8 (RFC 5958 2), version 1 is SEC1 (RFC 5915 3). */
static int eckey_dispatch(quic_derseq* c, u64 v, u8 out[32]) {
  if (v == 0) return eckey_pkcs8_at(c, out);
  return eckey_sec1_at(c, v, out);
}

int wired_eckey_p256_priv(quic_span key_der, u8 out[32]) {
  quic_derseq c;
  u64         v;
  if (!eckey_open(key_der, &c, &v)) return 0;
  return eckey_dispatch(&c, v, out);
}

/* RFC 8410 3. id-Ed25519 = 1.3.101.112. */
static const u8 eckey_oid_ed25519[] = {0x2b, 0x65, 0x70};

/* RFC 5280 4.1.1.2 / RFC 8410 7. privateKeyAlgorithm SEQUENCE{ id-Ed25519 }
 * (no parameters). Returns the encoded length, 0 on overflow. */
static usz eckey_build_ed25519_alg(quic_obuf* out) {
  u8        oid[8];
  quic_obuf o = quic_obuf_of(oid, sizeof(oid));
  if (!quic_selfcert_der_tlv(
          QUIC_DER_OID,
          quic_span_of(eckey_oid_ed25519, sizeof(eckey_oid_ed25519)), &o))
    return 0;
  if (!quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, quic_span_of(oid, o.len), out))
    return 0;
  return out->len;
}

/* RFC 8410 7. privateKey OCTET STRING wrapping CurvePrivateKey
 * OCTET STRING(seed). Returns the encoded length, 0 on overflow. */
static usz eckey_build_ed25519_privkey(const u8 seed[32], quic_obuf* out) {
  u8        inner[34];
  quic_obuf io = quic_obuf_of(inner, sizeof(inner));
  if (!quic_selfcert_der_tlv(
          QUIC_DER_OCTET_STRING, quic_span_of(seed, 32), &io))
    return 0;
  if (!quic_selfcert_der_tlv(
          QUIC_DER_OCTET_STRING, quic_span_of(inner, io.len), out))
    return 0;
  return out->len;
}

/* RFC 5958 2 / RFC 8410 7. version INTEGER 0. */
static const u8 eckey_version0[] = {0x02, 0x01, 0x00};

/* True if every part was encoded (non-zero length, or version's fixed
 * length). */
static int eckey_parts_ok(const quic_span* p) { return p[1].n && p[2].n; }

/* Concatenate version/alg/privateKey and wrap in the OneAsymmetricKey
 * SEQUENCE. */
static int eckey_assemble(const quic_span* parts, quic_obuf* out) {
  u8  body[64];
  usz off = 0;
  int ok  = 1;
  for (usz i = 0; i < 3; i++)
    ok &= quic_put_bytes(
        quic_mspan_of(body, sizeof(body)), &off,
        quic_span_of(parts[i].p, parts[i].n));
  if (!ok) return 0;
  return quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, quic_span_of(body, off), out);
}

int wired_eckey_ed25519_pkcs8_encode(const u8 seed[32], quic_obuf* out) {
  u8        alg[16], pk[40];
  quic_obuf ao      = quic_obuf_of(alg, sizeof(alg));
  quic_obuf po      = quic_obuf_of(pk, sizeof(pk));
  usz       an      = eckey_build_ed25519_alg(&ao);
  usz       pn      = eckey_build_ed25519_privkey(seed, &po);
  quic_span parts[] = {
      {eckey_version0, sizeof(eckey_version0)}, {alg, an}, {pk, pn}};
  if (!eckey_parts_ok(parts)) return 0;
  return eckey_assemble(parts, out);
}

/* RFC 8410 7. The inner CurvePrivateKey OCTET STRING value: exactly the
 * 32-byte key. */
static int eckey_curve25519_scalar(quic_span inner, u8 out[32]) {
  if (inner.n != 32) return 0;
  quic_memcpy(out, inner.p, 32);
  return 1;
}

/* RFC 8410 7. OneAsymmetricKey's privateKey field: an OCTET STRING wrapping
 * the CurvePrivateKey OCTET STRING. */
static int eckey_curve25519_privkey(quic_derseq* c, u8 out[32]) {
  quic_span   outer, inner;
  quic_derseq ic;
  if (!quic_derseq_next_tagged(c, QUIC_DER_OCTET_STRING, &outer)) return 0;
  quic_derseq_init(&ic, outer);
  if (!quic_derseq_next_tagged(&ic, QUIC_DER_OCTET_STRING, &inner)) return 0;
  return eckey_curve25519_scalar(inner, out);
}

/* RFC 5958 2 / RFC 8410 7. Open the OneAsymmetricKey SEQUENCE, requiring
 * version 0, and position c past privateKeyAlgorithm. */
static int eckey_curve25519_open(quic_span key_der, quic_derseq* c) {
  quic_span alg;
  u64       v;
  if (!eckey_open(key_der, c, &v)) return 0;
  if (v != 0) return 0;
  return quic_derseq_next_tagged(c, QUIC_DER_SEQUENCE, &alg);
}

int wired_eckey_curve25519_priv(quic_span key_der, u8 out[32]) {
  quic_derseq c;
  if (!eckey_curve25519_open(key_der, &c)) return 0;
  return eckey_curve25519_privkey(&c, out);
}
