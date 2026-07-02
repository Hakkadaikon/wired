#include "crypto/pki/encoding/x509/sigalgoid.h"

#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5758 3.2 / RFC 8017 A.2.4 signature OIDs (DER value bytes). */
static const u8 sao_ecdsa_sha256[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x02};
static const u8 sao_ecdsa_sha384[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x03};
static const u8 sao_rsa_sha256[]   = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x0b};
static const u8 sao_rsa_sha384[]   = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x0c};
static const u8 sao_rsa_sha512[]   = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x0d};

static const struct {
  const u8        *oid;
  usz              oid_len;
  quic_x509_sigalg alg;
} sao_table[] = {
    {sao_ecdsa_sha256,
     sizeof(sao_ecdsa_sha256),
     {QUIC_X509_SIG_ECDSA, QUIC_X509_HASH_SHA256}},
    {sao_ecdsa_sha384,
     sizeof(sao_ecdsa_sha384),
     {QUIC_X509_SIG_ECDSA, QUIC_X509_HASH_SHA384}},
    {sao_rsa_sha256,
     sizeof(sao_rsa_sha256),
     {QUIC_X509_SIG_RSA_PKCS1, QUIC_X509_HASH_SHA256}},
    {sao_rsa_sha384,
     sizeof(sao_rsa_sha384),
     {QUIC_X509_SIG_RSA_PKCS1, QUIC_X509_HASH_SHA384}},
    {sao_rsa_sha512,
     sizeof(sao_rsa_sha512),
     {QUIC_X509_SIG_RSA_PKCS1, QUIC_X509_HASH_SHA512}},
};

int quic_x509_sigalg_lookup(quic_span oid, quic_x509_sigalg *out) {
  usz n = sizeof(sao_table) / sizeof(sao_table[0]);
  for (usz i = 0; i < n; i++)
    if (quic_der_oid_equal(
            oid, quic_span_of(sao_table[i].oid, sao_table[i].oid_len))) {
      *out = sao_table[i].alg;
      return 1;
    }
  return 0;
}
