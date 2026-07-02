#ifndef QUIC_CASTORE_CHAINVERIFY_H
#define QUIC_CASTORE_CHAINVERIFY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 6.1.3. Verify that cert (DER) carries a valid signature by
 * issuer_cert's public key: the sigAlg's digest over cert's tbsCertificate,
 * checked against the issuer key (ECDSA P-256/P-384 or RSA PKCS#1 v1.5). The
 * issuer key type selects the algorithm. Returns 1 if the signature verifies,
 * else 0. */
int quic_castore_verify_signed_by(quic_span cert, quic_span issuer_cert);

#endif
