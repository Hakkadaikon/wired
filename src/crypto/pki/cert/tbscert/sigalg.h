#ifndef TBSCERT_SIGALG_H
#define TBSCERT_SIGALG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/cert/tbscert/fields.h"

/* RFC 5280 4.1.2.3. The OID inside the tbs signature AlgorithmIdentifier.
 * Views into the tbs buffer. Returns 1 ok, 0 on malformed input. */
int tbscert_sigalg_oid(const tbscert* t, wired_span* oid);

/* RFC 5280 4.1.1.2. 1 if the tbs signature AlgorithmIdentifier byte-equals
 * the outer signatureAlgorithm -- its OID and its parameter octets (the
 * bytes after the OID, empty when absent); 0 otherwise (a mismatch is a
 * malformed certificate). */
int tbscert_sigalg_matches(
    const tbscert* t, wired_span outer_oid, wired_span outer_params);

#endif
