#include "crypto/pki/encoding/eckey/eckey.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* Open the outer SEQUENCE and read the leading version INTEGER. */
static int eckey_open(wired_span der, derseq* c, u64* v) {
  wired_span body, iv;
  if (!der_seq(der, &body)) {
    return 0;
  }
  derseq_init(c, body);
  return derseq_next_tagged(c, DER_INTEGER, &iv) && der_uint(iv.p, iv.n, v);
}

/* RFC 5915 3. privateKey OCTET STRING: exactly the 32-byte scalar. */
static int eckey_scalar(derseq* c, u8 out[32]) {
  wired_span priv;
  if (!derseq_next_tagged(c, DER_OCTET_STRING, &priv)) {
    return 0;
  }
  if (priv.n != 32) {
    return 0;
  }
  bytes_memcpy(out, priv.p, 32);
  return 1;
}

/* RFC 5915 3. SEC1 rest after the version: version must be 1. */
static int eckey_sec1_at(derseq* c, u64 v, u8 out[32]) {
  if (v != 1) {
    return 0;
  }
  return eckey_scalar(c, out);
}

/* RFC 5958 2. Skip AlgorithmIdentifier, view the privateKey octets. */
static int eckey_pkcs8_unwrap(derseq* c, wired_span* inner) {
  wired_span alg;
  return derseq_next_tagged(c, DER_SEQUENCE, &alg) &&
         derseq_next_tagged(c, DER_OCTET_STRING, inner);
}

/* RFC 5958 2. The privateKey octets hold a SEC1 ECPrivateKey. */
static int eckey_pkcs8_at(derseq* c, u8 out[32]) {
  wired_span inner;
  derseq     ic;
  u64        iv;
  if (!eckey_pkcs8_unwrap(c, &inner)) {
    return 0;
  }
  if (!eckey_open(inner, &ic, &iv)) {
    return 0;
  }
  return eckey_sec1_at(&ic, iv, out);
}

/* Version 0 is PKCS#8 (RFC 5958 2), version 1 is SEC1 (RFC 5915 3). */
static int eckey_dispatch(derseq* c, u64 v, u8 out[32]) {
  if (v == 0) {
    return eckey_pkcs8_at(c, out);
  }
  return eckey_sec1_at(c, v, out);
}

int wired_eckey_p256_priv(wired_span key_der, u8 out[32]) {
  derseq c;
  u64    v;
  if (!eckey_open(key_der, &c, &v)) {
    return 0;
  }
  return eckey_dispatch(&c, v, out);
}

/* RFC 8410 7 / 10.3. OneAsymmetricKey { version INTEGER 0,
 * AlgorithmIdentifier { id-Ed25519 1.3.101.112 }, privateKey OCTET STRING {
 * CurvePrivateKey OCTET STRING (32) } }: every length is fixed, so the
 * encoding is this 16-byte header followed by the seed. */
static const u8 eckey_ed25519_head[] = {0x30, 0x2e, 0x02, 0x01, 0x00, 0x30,
                                        0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                                        0x04, 0x22, 0x04, 0x20};
#define ECKEY_ED25519_PKCS8_LEN (sizeof(eckey_ed25519_head) + 32)

int wired_eckey_ed25519_pkcs8_encode(const u8 seed[32], wired_obuf* out) {
  wired_mspan m   = wired_mspan_of(out->p, out->cap);
  usz         off = 0;
  if (out->cap < ECKEY_ED25519_PKCS8_LEN) {
    return 0;
  }
  bytes_put(
      m, &off, wired_span_of(eckey_ed25519_head, sizeof(eckey_ed25519_head)));
  bytes_put(m, &off, wired_span_of(seed, 32));
  out->len = off;
  return 1;
}

/* RFC 8410 7. The inner CurvePrivateKey OCTET STRING value: exactly the
 * 32-byte key. */
static int eckey_curve25519_scalar(wired_span inner, u8 out[32]) {
  if (inner.n != 32) {
    return 0;
  }
  bytes_memcpy(out, inner.p, 32);
  return 1;
}

/* RFC 8410 7. OneAsymmetricKey's privateKey field: an OCTET STRING wrapping
 * the CurvePrivateKey OCTET STRING. */
static int eckey_curve25519_privkey(derseq* c, u8 out[32]) {
  wired_span outer, inner;
  derseq     ic;
  if (!derseq_next_tagged(c, DER_OCTET_STRING, &outer)) {
    return 0;
  }
  derseq_init(&ic, outer);
  if (!derseq_next_tagged(&ic, DER_OCTET_STRING, &inner)) {
    return 0;
  }
  return eckey_curve25519_scalar(inner, out);
}

/* RFC 5958 2 / RFC 8410 7. Open the OneAsymmetricKey SEQUENCE, read its
 * version, and position c past privateKeyAlgorithm. */
static int eckey_curve25519_open(wired_span key_der, derseq* c, u64* v) {
  wired_span alg;
  if (!eckey_open(key_der, c, v)) {
    return 0;
  }
  return derseq_next_tagged(c, DER_SEQUENCE, &alg);
}

/* RFC 5958 2. publicKey is [1] IMPLICIT BIT STRING (primitive 0x81), the
 * last field, after the optional attributes [0]. */
#define ECKEY_PUBKEY_TAG 0x81

/* 1 if the fields after privateKey end with publicKey [1]. */
static int eckey_curve25519_has_pub(derseq* c) {
  u8         tag, last = 0;
  wired_span val;
  while (derseq_next(c, &tag, &val)) {
    last = tag;
  }
  return last == ECKEY_PUBKEY_TAG;
}

/* RFC 5958 2 / RFC 8410 Appendix A: version is 0 without publicKey and 1
 * with it; anything else is rejected. */
int wired_eckey_curve25519_priv(wired_span key_der, u8 out[32]) {
  derseq c;
  u64    v;
  if (!eckey_curve25519_open(key_der, &c, &v)) {
    return 0;
  }
  if (!eckey_curve25519_privkey(&c, out)) {
    return 0;
  }
  return v == (u64)eckey_curve25519_has_pub(&c);
}
