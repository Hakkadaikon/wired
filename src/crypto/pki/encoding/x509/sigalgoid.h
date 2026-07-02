#ifndef QUIC_X509_SIGALGOID_H
#define QUIC_X509_SIGALGOID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.1.2. The signature-algorithm allowlist: OID -> issuer key
 * kind + digest. Unknown OIDs (md5/sha1/sha224 legacies, RSA-PSS cert
 * signatures) fail the lookup, so they are rejected by construction. */

enum { QUIC_X509_SIG_ECDSA = 1, QUIC_X509_SIG_RSA_PKCS1 = 2 };
enum {
  QUIC_X509_HASH_SHA256 = 1,
  QUIC_X509_HASH_SHA384 = 2,
  QUIC_X509_HASH_SHA512 = 3
};

typedef struct {
  u8 key_kind;  /* QUIC_X509_SIG_* */
  u8 hash_kind; /* QUIC_X509_HASH_* */
} quic_x509_sigalg;

/* Look up a signatureAlgorithm OID (DER value bytes). Returns 1 and fills
 * *out for a listed algorithm, 0 for anything else (fail closed). */
int quic_x509_sigalg_lookup(quic_span oid, quic_x509_sigalg *out);

#endif
