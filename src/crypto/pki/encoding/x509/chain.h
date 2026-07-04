#ifndef QUIC_X509_CHAIN_H
#define QUIC_X509_CHAIN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.4 / 4.1.2.6. Locate the issuer and subject Name SEQUENCEs
 * inside a tbsCertificate. The view (tag+length header included) points into
 * the caller's buffer. Returns 1 ok, 0 on malformed input. */
int quic_x509_issuer(quic_span tbs, quic_span* issuer);
int quic_x509_subject(quic_span tbs, quic_span* subject);

/* RFC 5280 4.1.2.4. Byte-equal Name comparison (cert A issuer vs cert B
 * subject). Returns 1 if equal, 0 otherwise. */
int quic_x509_dn_equal(quic_span a, quic_span b);

#endif
