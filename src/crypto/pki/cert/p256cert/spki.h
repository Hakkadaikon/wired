#ifndef QUIC_P256CERT_SPKI_H
#define QUIC_P256CERT_SPKI_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.7 / SEC1 C.3. Build a P-256 SubjectPublicKeyInfo:
 *   SEQUENCE { AlgorithmIdentifier{ id-ecPublicKey, secp256r1 },
 *              BIT STRING(0x00 || 0x04 || X(32) || Y(32)) }
 * from the affine public key (x, y) into out, setting out->len to the whole
 * SEQUENCE length. Returns 1 ok, 0 if it would not fit. */
int quic_p256cert_spki(const u8 x[32], const u8 y[32], quic_obuf *out);

#endif
