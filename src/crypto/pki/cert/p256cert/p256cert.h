#ifndef QUIC_P256CERT_P256CERT_H
#define QUIC_P256CERT_P256CERT_H

#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1 / SEC1. Build a self-signed ECDSA P-256 X.509 certificate
 * (self-issued CN=localhost, fixed validity, secp256r1 SPKI,
 * ecdsa-with-SHA256 signature) from the private scalar and its affine public
 * key into out (cap octets). Sets *len. Returns 1 ok, 0 on failure. */
int quic_p256cert_build(
    const u8 priv[32],
    const u8 pub_x[32],
    const u8 pub_y[32],
    u8      *out,
    usz      cap,
    usz     *len);

#endif
