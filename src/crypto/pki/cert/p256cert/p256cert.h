#ifndef QUIC_P256CERT_P256CERT_H
#define QUIC_P256CERT_P256CERT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* An ECDSA P-256 signing key: the private scalar and its affine public key,
 * each 32 bytes, caller-owned. */
typedef struct {
  const u8 *priv;
  const u8 *x;
  const u8 *y;
} quic_p256cert_key;

/* RFC 5280 4.1 / SEC1. Build a self-signed ECDSA P-256 X.509 certificate
 * (self-issued CN=localhost, fixed validity, secp256r1 SPKI,
 * ecdsa-with-SHA256 signature) from the key into out, setting out->len.
 * Returns 1 ok, 0 on failure. */
int quic_p256cert_build(const quic_p256cert_key *k, quic_obuf *out);

#endif
