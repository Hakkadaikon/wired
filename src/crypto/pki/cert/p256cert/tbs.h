#ifndef QUIC_P256CERT_TBS_H
#define QUIC_P256CERT_TBS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1. Build a v3 TBSCertificate (self-issued CN=localhost, fixed
 * validity, ecdsa-with-SHA256 signature AlgID, secp256r1 SPKI) from the affine
 * public key into out, setting out->len. Returns 1 ok, 0 on failure. */
int quic_p256cert_tbs(const u8 x[32], const u8 y[32], quic_obuf* out);

/* RFC 5480 2.1.1. signatureAlgorithm SEQUENCE { ecdsa-with-SHA256 } (no
 * params). Writes the whole TLV into out. Returns its length, 0 on failure. */
usz quic_p256cert_sigalg(quic_obuf* out);

#endif
