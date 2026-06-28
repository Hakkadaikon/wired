#ifndef QUIC_CASTORE_CHAINVERIFY_H
#define QUIC_CASTORE_CHAINVERIFY_H

#include "sys/syscall.h"

/* RFC 5280 6.1.3. Verify that cert (DER, cert..+cert_len) carries a valid
 * signature by issuer_cert's public key: SHA-256 over cert's tbsCertificate,
 * checked against the issuer key (ECDSA P-256 or RSA PKCS#1 v1.5). The issuer
 * key type selects the algorithm. Returns 1 if the signature verifies, else 0. */
int quic_castore_verify_signed_by(const u8 *cert, usz cert_len,
                                  const u8 *issuer_cert, usz issuer_len);

#endif
