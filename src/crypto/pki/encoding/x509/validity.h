#ifndef QUIC_X509_VALIDITY_H
#define QUIC_X509_VALIDITY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.5. Validity ::= SEQUENCE { notBefore Time, notAfter Time }.
 * Descends tbsCertificate, parses both Time values (UTCTime YYMMDDHHMMSSZ or
 * GeneralizedTime YYYYMMDDHHMMSSZ) and compares against now, given as the
 * decimal YYYYMMDDHHMMSS (e.g. 20260628030430). Returns 1 if
 * notBefore <= now <= notAfter, 0 otherwise or on malformed input. */
int quic_x509_validity_ok(quic_span tbs, u64 now);

#endif
