#include "crypto/pki/encoding/eckey/eckey.h"

#include "common/bytes/util/bytes.h"
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
