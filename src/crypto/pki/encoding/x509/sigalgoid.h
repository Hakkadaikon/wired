#ifndef X509_SIGALGOID_H
#define X509_SIGALGOID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.1.2. The signature-algorithm allowlist: OID -> issuer key
 * kind + digest. Unknown OIDs (md5/sha1/sha224WithRSAEncryption legacies,
 * RSA-PSS cert signatures) fail the lookup, so they are rejected by
 * construction. */

enum { X509_SIG_ECDSA = 1, X509_SIG_RSA_PKCS1 = 2 };
enum {
  X509_HASH_SHA256 = 1,
  X509_HASH_SHA384 = 2,
  X509_HASH_SHA512 = 3,
  X509_HASH_SHA224 = 4
};

/** A resolved signatureAlgorithm: issuer key kind and digest kind. */
typedef struct {
  u8 key_kind;  /* X509_SIG_* */
  u8 hash_kind; /* X509_HASH_* */
} x509_sigalg;

/* Look up a signatureAlgorithm OID (DER value bytes). Returns 1 and fills
 * *out for a listed algorithm, 0 for anything else (fail closed). */
int x509_sigalg_lookup(wired_span oid, x509_sigalg* out);

#endif
