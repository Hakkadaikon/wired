#ifndef QUIC_X509_RSA_PUBKEY_H
#define QUIC_X509_RSA_PUBKEY_H

#include "common/platform/sys/syscall.h"

/* RFC 8017 A.1.1. RSAPublicKey ::= SEQUENCE { modulus INTEGER (n),
 * publicExponent INTEGER (e) }. spki_key is the BIT STRING value of an
 * rsaEncryption subjectPublicKey, leading 0x00 unused-bits octet included.
 * Views n and e (big-endian INTEGER values) into spki_key. Also validates
 * the key: n must be canonical, odd, and >= 2048 bits; e must be canonical,
 * odd, and in [3, 2^64). Returns 1 ok, 0 on malformed or invalid input. */
int quic_x509_rsa_pubkey(
    const u8  *spki_key,
    usz        key_len,
    const u8 **n,
    usz       *n_len,
    const u8 **e,
    usz       *e_len);

#endif
