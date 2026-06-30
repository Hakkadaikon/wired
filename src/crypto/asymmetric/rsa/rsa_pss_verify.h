#ifndef QUIC_RSA_RSA_PSS_VERIFY_H
#define QUIC_RSA_RSA_PSS_VERIFY_H

#include "common/platform/sys/syscall.h"

/* RFC 8017 8.1.2. RSASSA-PSS verification with SHA-256, MGF1-SHA-256 and salt
 * length 32 (TLS rsa_pss_rsae_sha256). n and sig are big-endian; mhash is the
 * 32-byte SHA-256 message digest. Public exponent fixed at e=65537. Returns 1
 * if the signature is valid, else 0. */
int quic_rsa_pss_verify(
    const u8 *n,
    usz       n_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *mhash,
    usz       hash_len);

#endif
