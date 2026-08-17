#ifndef X509_KEYID_H
#define X509_KEYID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.1. Locate the authorityKeyIdentifier extension (OID
 * 2.5.29.35) and view its extnValue (AuthorityKeyIdentifier SEQUENCE).
 * Returns 1 if present, 0 if absent or malformed. RFC 5280 4.2.1.2 does not
 * require key-identifier matching during path validation; recognizing the
 * extension is sufficient. */
int x509_authority_key_id(wired_span tbs, wired_span* val);

/* RFC 5280 4.2.1.2. Locate the subjectKeyIdentifier extension (OID
 * 2.5.29.14) and view its extnValue (KeyIdentifier OCTET STRING). Returns 1
 * if present, 0 if absent or malformed. */
int x509_subject_key_id(wired_span tbs, wired_span* val);

#endif
