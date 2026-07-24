#ifndef QUIC_X509_KEYUSAGE_H
#define QUIC_X509_KEYUSAGE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.3. 1 if the cert may sign other certificates: the
 * keyUsage extension is absent (DER default: unconstrained), or present
 * with the keyCertSign bit set. 0 if keyUsage is present without
 * keyCertSign, or malformed. */
int quic_x509_can_sign_certs(quic_span tbs);

#endif
