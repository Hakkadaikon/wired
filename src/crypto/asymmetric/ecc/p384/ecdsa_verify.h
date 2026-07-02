#ifndef QUIC_P384_ECDSA_VERIFY_H
#define QUIC_P384_ECDSA_VERIFY_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 6.4.2 ECDSA verification on P-384. pub_x/pub_y is the public
 * key, sig_r/sig_s the signature, msg_hash a 48-byte digest (a shorter hash
 * must be left-zero-extended to 48 by the caller). Returns 1 if the signature
 * is valid, else 0. */
int quic_ecdsa_p384_verify(
    const u8 pub_x[48],
    const u8 pub_y[48],
    const u8 sig_r[48],
    const u8 sig_s[48],
    const u8 msg_hash[48]);

#endif
