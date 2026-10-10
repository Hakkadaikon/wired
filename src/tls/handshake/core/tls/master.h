#ifndef TLS_MASTER_H
#define TLS_MASTER_H

#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 7.1: Master Secret from the Handshake Secret.
 * derived = Derive-Secret(Handshake, "derived", ""); then
 * Master Secret = HKDF-Extract(derived, 0). Writes a 32-byte secret. */
void tls_master_secret(const u8* hs_secret, u8* out);

/* Same as tls_master_secret over suite's hash (Hash.length in and out). */
void tls_master_secret_suite(u16 suite, const u8* hs_secret, u8* out);

#endif
