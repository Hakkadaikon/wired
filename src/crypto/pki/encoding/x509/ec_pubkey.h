#ifndef QUIC_X509_EC_PUBKEY_H
#define QUIC_X509_EC_PUBKEY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* SEC1 2.3.3 / RFC 5480 2.2. P-256 point: 0x04 || X(32) || Y(32)
 * (uncompressed), or 0x02 || X(32) / 0x03 || X(32) (compressed, tag selects
 * the parity of Y; Y is recovered from the curve equation). spki_key is the
 * BIT STRING value of an id-ecPublicKey subjectPublicKey, leading 0x00
 * unused-bits octet included. Copies X and Y out. Returns 1 ok, 0 if the key
 * is malformed, wrong length, or (compressed) not a valid curve point. */
int quic_x509_ec_pubkey(quic_span spki_key, u8 x[32], u8 y[32]);

/* SEC1 2.3.3 / RFC 5480 2.2. The P-384 form: 0x00 unused-bits then either
 * 0x04 || X48 || Y48 (uncompressed) or 0x02/0x03 || X48 (compressed).
 * Returns 1 ok, 0 if the BIT STRING is not a valid P-384 point encoding. */
int quic_x509_ec_pubkey384(quic_span spki_key, u8 x[48], u8 y[48]);

#endif
