#ifndef QUIC_X509_SAN_H
#define QUIC_X509_SAN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.6 / RFC 6125. 1 if a subjectAltName dNSName matches the
 * hostname; 0 otherwise. A leading "*." wildcard matches one label only. */
int quic_x509_san_matches(quic_span tbs, quic_span hostname);

#endif
