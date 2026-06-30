#ifndef QUIC_P256_ECDSA_VERIFY_H
#define QUIC_P256_ECDSA_VERIFY_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 Section 6.4.2 ECDSA signature verification on P-256.
 * All inputs are big-endian 32-byte integers. The public key is the affine
 * (x, y) of Q. msg_hash is the SHA-256 digest of the signed message.
 * Returns 1 if the signature is valid, 0 otherwise. */
int quic_ecdsa_p256_verify(
    const u8 pub_x[32],
    const u8 pub_y[32],
    const u8 sig_r[32],
    const u8 sig_s[32],
    const u8 msg_hash[32]);

#endif
