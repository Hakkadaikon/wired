#ifndef P521_ECDSA_VERIFY_H
#define P521_ECDSA_VERIFY_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 6.4.2 ECDSA verification on P-521. pub_x/pub_y is the public
 * key and sig_r/sig_s the signature, each 66 big-endian bytes. digest is the
 * raw message hash of any length; its leftmost 521 bits become e (FIPS
 * 186-4 6.4, so a 512-bit SHA-512 digest is used whole). Returns 1 if the
 * signature is valid, else 0. */
int ecdsa_p521_verify(
    const u8  pub_x[66],
    const u8  pub_y[66],
    const u8  sig_r[66],
    const u8  sig_s[66],
    const u8* digest,
    usz       digest_len);

#endif
