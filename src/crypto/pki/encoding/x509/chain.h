#ifndef QUIC_X509_CHAIN_H
#define QUIC_X509_CHAIN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.4 / 4.1.2.6. Locate the issuer and subject Name SEQUENCEs
 * inside a tbsCertificate. The view (tag+length header included) points into
 * the caller's buffer. Returns 1 ok, 0 on malformed input. */
int x509_issuer(wired_span tbs, wired_span* issuer);
int x509_subject(wired_span tbs, wired_span* subject);

/* RFC 5280 4.1.2.4. Byte-equal Name comparison (cert A issuer vs cert B
 * subject). Returns 1 if equal, 0 otherwise. */
int x509_dn_equal(wired_span a, wired_span b);

#endif
