#ifndef QUIC_CASTORE_PATHVALIDATE_H
#define QUIC_CASTORE_PATHVALIDATE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/trust/castore/castore.h"

/* RFC 5280 6.1. Validate a certificate path certs[0..n_certs) ordered leaf
 * first. certs[0] (the leaf, a server certificate) must permit
 * id-kp-serverAuth per its extKeyUsage (RFC 5280 4.2.1.12; absent extension
 * is unrestricted). For each adjacent pair certs[i]/certs[i+1] the issuer
 * Name of certs[i] must equal the subject Name of certs[i+1], certs[i+1]
 * must be a CA permitted to sign certificates (basicConstraints cA TRUE and,
 * if keyUsage is present, keyCertSign set), and certs[i]'s signature must
 * verify under certs[i+1]'s key. The tail certs[n_certs-1] must chain to a
 * trust anchor in s: a registered root whose subject equals the tail's issuer
 * (and which signs the tail). Returns 1 if the whole path validates, else 0. */
int quic_castore_validate_chain(
    const quic_castore* s, const quic_span* certs, usz n_certs);

#endif
