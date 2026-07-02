#ifndef QUIC_TBSCERT_SIGALG_H
#define QUIC_TBSCERT_SIGALG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/cert/tbscert/fields.h"

/* RFC 5280 4.1.2.3. The OID inside the tbs signature AlgorithmIdentifier.
 * Views into the tbs buffer. Returns 1 ok, 0 on malformed input. */
int quic_tbscert_sigalg_oid(const quic_tbscert *t, quic_span *oid);

/* RFC 5280 4.1.1.2. 1 if the tbs signature OID byte-equals the outer
 * signatureAlgorithm OID; 0 otherwise (a mismatch is a malformed certificate).
 */
int quic_tbscert_sigalg_matches(const quic_tbscert *t, quic_span outer_oid);

#endif
