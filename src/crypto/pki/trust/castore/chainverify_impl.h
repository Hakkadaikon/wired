#ifndef CASTORE_CHAINVERIFY_IMPL_H
#define CASTORE_CHAINVERIFY_IMPL_H

#include "common/bytes/span/span.h"

/* RFC 5480 2.1.1 / FIPS 186-4 6.1.1, 6.4. Verify an ECDSA signature sig over
 * digest hash with the issuer key (subjectPublicKey BIT STRING value) whose
 * curve is the namedCurve in the issuer's tbsCertificate. Returns 0 when the
 * parameters are not a supported namedCurve or the digest is weaker than
 * the curve. */
int castore_verify_ecdsa_issuer(
    wired_span tbs, wired_span key, wired_span sig, wired_span hash);

#endif
