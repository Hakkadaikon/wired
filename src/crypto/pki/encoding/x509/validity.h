#ifndef X509_VALIDITY_H
#define X509_VALIDITY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.5. Validity ::= SEQUENCE { notBefore Time, notAfter Time }.
 * Descends tbsCertificate, parses both Time values (UTCTime YYMMDDHHMMSSZ or
 * GeneralizedTime YYYYMMDDHHMMSSZ) and compares against now, given as the
 * decimal YYYYMMDDHHMMSS (e.g. 20260628030430). Returns 1 if
 * notBefore <= now <= notAfter, 0 otherwise or on malformed input. */
int x509_validity_ok(wired_span tbs, u64 now);

/* RFC 5280 4.1.2.5.1. Encode a decimal YYYYMMDDHHMMSS (the same convention as
 * x509_validity_ok's now, e.g. from clock_epoch_to_ymdhms) as an
 * ASN.1 UTCTime value "YYMMDDHHMMSSZ" (13 bytes, no NUL) into out[13]. The
 * century digits are dropped per the UTCTime encoding rule (RFC 5280
 * 4.1.2.5.1: 1950-2049 only); a year outside that range wraps mod 100. */
void x509_utctime_encode(u64 ymdhms, u8 out[13]);

#endif
