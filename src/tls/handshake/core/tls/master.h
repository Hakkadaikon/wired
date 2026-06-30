#ifndef QUIC_TLS_MASTER_H
#define QUIC_TLS_MASTER_H

#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 7.1: Master Secret from the Handshake Secret.
 * derived = Derive-Secret(Handshake, "derived", ""); then
 * Master Secret = HKDF-Extract(derived, 0). Writes a 32-byte secret. */
void quic_tls_master_secret(const u8 hs_secret[QUIC_HKDF_PRK],
                            u8 out[QUIC_HKDF_PRK]);

#endif
