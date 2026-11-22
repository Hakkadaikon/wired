#include "crypto/pki/encoding/x509/sigalgoid.h"

#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/sigalgoid_impl.h"

/* RFC 5758 3.2 / RFC 8017 A.2.4 signature OIDs (DER value bytes). */
static const u8 sao_ecdsa_sha224[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x01};
static const u8 sao_ecdsa_sha256[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x02};
static const u8 sao_ecdsa_sha384[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x03};
static const u8 sao_ecdsa_sha512[] = {0x2a, 0x86, 0x48, 0xce,
                                      0x3d, 0x04, 0x03, 0x04};
static const u8 sao_rsa_sha256[]   = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x0b};
static const u8 sao_rsa_sha384[]   = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x0c};
static const u8 sao_rsa_sha512[]   = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 0x01, 0x01, 0x0d};
/* RFC 8410 3: id-Ed25519, 1.3.101.112. */
static const u8 sao_ed25519[] = {0x2b, 0x65, 0x70};

static const struct {
  const u8*   oid;
  usz         oid_len;
  x509_sigalg alg;
} sao_table[] = {
    {sao_ecdsa_sha224,
     sizeof(sao_ecdsa_sha224),
     {X509_SIG_ECDSA, X509_HASH_SHA224}},
    {sao_ecdsa_sha256,
     sizeof(sao_ecdsa_sha256),
     {X509_SIG_ECDSA, X509_HASH_SHA256}},
    {sao_ecdsa_sha384,
     sizeof(sao_ecdsa_sha384),
     {X509_SIG_ECDSA, X509_HASH_SHA384}},
    {sao_ecdsa_sha512,
     sizeof(sao_ecdsa_sha512),
     {X509_SIG_ECDSA, X509_HASH_SHA512}},
    {sao_rsa_sha256,
     sizeof(sao_rsa_sha256),
     {X509_SIG_RSA_PKCS1, X509_HASH_SHA256}},
    {sao_rsa_sha384,
     sizeof(sao_rsa_sha384),
     {X509_SIG_RSA_PKCS1, X509_HASH_SHA384}},
    {sao_rsa_sha512,
     sizeof(sao_rsa_sha512),
     {X509_SIG_RSA_PKCS1, X509_HASH_SHA512}},
    {sao_ed25519, sizeof(sao_ed25519), {X509_SIG_ED25519, X509_HASH_NONE}},
};

/* RFC 4055 3.1: id-RSASSA-PSS (1.2.840.113549.1.1.10). */
static const u8 sao_rsa_pss[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                 0x0d, 0x01, 0x01, 0x0a};

static int sao_table_find(wired_span oid, x509_sigalg* out) {
  usz n = sizeof(sao_table) / sizeof(sao_table[0]);
  for (usz i = 0; i < n; i++) {
    if (der_oid_equal(
            oid, wired_span_of(sao_table[i].oid, sao_table[i].oid_len))) {
      *out = sao_table[i].alg;
      return 1;
    }
  }
  return 0;
}

int x509_sigalg_lookup(wired_span oid, wired_span params, x509_sigalg* out) {
  if (der_oid_equal(oid, wired_span_of(sao_rsa_pss, sizeof(sao_rsa_pss)))) {
    return x509_sigalg_pss_params(params, out);
  }
  return sao_table_find(oid, out);
}
