#ifndef QUIC_RSA_RSA_VERIFY_H
#define QUIC_RSA_RSA_VERIFY_H

#include "common/platform/sys/syscall.h"

/* RFC 8017 8.2.2. RSASSA-PKCS1-v1_5 verification with SHA-256 and the
 * common public exponent e=65537. n and sig are big-endian; msg_hash is a
 * 32-byte SHA-256 digest. Returns 1 if the signature is valid, else 0. */
int quic_rsa_pkcs1_verify(
    const u8 *n,
    usz       n_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *msg_hash,
    usz       hash_len);

#endif
