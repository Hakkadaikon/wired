#ifndef QUIC_RSA_RSA_PSS_VERIFY_H
#define QUIC_RSA_RSA_PSS_VERIFY_H

#include "crypto/asymmetric/rsa/rsa_verify.h"

/* RFC 8017 8.1.2. RSASSA-PSS verification with SHA-256, MGF1-SHA-256 and salt
 * length 32 (TLS rsa_pss_rsae_sha256). sig is big-endian; mhash is the
 * 32-byte SHA-256 message digest. pub->e must be F4 (65537); anything else is
 * rejected. Returns 1 if the signature is valid, else 0. */
int quic_rsa_pss_verify(
    const quic_rsa_pub* pub, quic_span sig, quic_span mhash);

#endif
