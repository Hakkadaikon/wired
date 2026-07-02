#ifndef QUIC_X509_EC_PUBKEY_H
#define QUIC_X509_EC_PUBKEY_H

#include "common/platform/sys/syscall.h"

/* SEC1 2.3.3. Uncompressed P-256 point 0x04 || X(32) || Y(32). spki_key is
 * the BIT STRING value of an id-ecPublicKey subjectPublicKey, leading 0x00
 * unused-bits octet included. Copies X and Y out. Returns 1 ok, 0 if the
 * key is not a 65-byte uncompressed point. */
int quic_x509_ec_pubkey(const u8 *spki_key, usz key_len, u8 x[32], u8 y[32]);

/* SEC1 2.3.3. The 98-byte P-384 form: 0x00 unused-bits then 0x04 || X48 ||
 * Y48. Returns 1 ok, 0 if the BIT STRING is not a P-384 uncompressed point. */
int quic_x509_ec_pubkey384(const u8 *spki_key, usz key_len, u8 x[48], u8 y[48]);

#endif
