#ifndef RSA_RSA_PSS_VERIFY_H
#define RSA_RSA_PSS_VERIFY_H

#include "crypto/asymmetric/rsa/pss.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"

/* RFC 8017 8.1.2. RSASSA-PSS verification under cfg (digest, MGF1 digest
 * and salt length). sig is big-endian; mhash is the cfg->h.len-octet
 * message digest. pub->e must be F4 (65537); anything else is rejected.
 * Returns 1 if the signature is valid, else 0. */
int rsa_pss_verify_cfg(
    const rsa_pub*     pub,
    wired_span         sig,
    wired_span         mhash,
    const rsa_pss_cfg* cfg);

/* rsa_pss_verify_cfg with SHA-256, MGF1-SHA-256 and salt length 32 (TLS
 * rsa_pss_rsae_sha256); mhash is the 32-byte SHA-256 digest. */
int rsa_pss_verify(const rsa_pub* pub, wired_span sig, wired_span mhash);

#endif
