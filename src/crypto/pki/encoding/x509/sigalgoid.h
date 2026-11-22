#ifndef X509_SIGALGOID_H
#define X509_SIGALGOID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.1.2. The signature-algorithm allowlist: OID (+ parameters
 * for RSASSA-PSS) -> issuer key kind + digest. Unknown OIDs
 * (md5/sha1/sha224WithRSAEncryption legacies) fail the lookup, so they are
 * rejected by construction.
 *
 * RFC 4055 3.1 id-RSASSA-PSS resolves only with explicit parameters naming
 * SHA-256, SHA-384 or SHA-512 as hashAlgorithm, MGF1 over that same hash as
 * maskGenAlgorithm, saltLength equal to the hash length (the RFC 8446 4.2.3
 * rsa_pss_* rule, and what CAs issue), and trailerField absent (its only
 * permitted value is the DEFAULT 1, which DER omits). The
 * SHA-1 defaults, any other hash or mask, and every other salt length fail
 * closed. */

enum {
  X509_SIG_ECDSA     = 1,
  X509_SIG_RSA_PKCS1 = 2,
  X509_SIG_ED25519   = 3,
  X509_SIG_RSA_PSS   = 4
};
/* X509_HASH_NONE: the signature covers the tbsCertificate itself, with no
 * separate digest step (RFC 8410 6, PureEdDSA). */
enum {
  X509_HASH_SHA256 = 1,
  X509_HASH_SHA384 = 2,
  X509_HASH_SHA512 = 3,
  X509_HASH_SHA224 = 4,
  X509_HASH_NONE   = 5
};

/** A resolved signatureAlgorithm: issuer key kind and digest kind. */
typedef struct {
  u8 key_kind;  /* X509_SIG_* */
  u8 hash_kind; /* X509_HASH_* */
} x509_sigalg;

/* Look up a signatureAlgorithm OID (DER value bytes) and its parameter
 * octets (the TLVs after the OID, empty when absent; consulted for
 * RSASSA-PSS only). Returns 1 and fills *out for a listed algorithm, 0 for
 * anything else (fail closed). An X509_SIG_RSA_PSS result implies MGF1 over
 * hash_kind and a salt as long as that digest. */
int x509_sigalg_lookup(wired_span oid, wired_span params, x509_sigalg* out);

#endif
