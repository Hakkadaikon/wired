#ifndef QUIC_CASTORE_PATHVALIDATE_H
#define QUIC_CASTORE_PATHVALIDATE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/trust/castore/castore.h"

/* RFC 5280 6.1. Validate a certificate path certs[0..n_certs) ordered leaf
 * first. For each adjacent pair certs[i]/certs[i+1] the issuer Name of certs[i]
 * must equal the subject Name of certs[i+1] and certs[i]'s signature must
 * verify under certs[i+1]'s key. The tail certs[n_certs-1] must chain to a
 * trust anchor in s: a registered root whose subject equals the tail's issuer
 * (and which signs the tail). Returns 1 if the whole path validates, else 0. */
int quic_castore_validate_chain(
    const quic_castore *s, const quic_span *certs, usz n_certs);

#endif
