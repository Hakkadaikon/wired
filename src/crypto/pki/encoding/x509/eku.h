#ifndef QUIC_X509_EKU_H
#define QUIC_X509_EKU_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* id-kp-serverAuth = 1.3.6.1.5.5.7.3.1 (RFC 5280 4.2.1.12 / RFC 9110). */
extern const u8 quic_x509_oid_server_auth[8];

/* RFC 5280 4.2.1.12. 1 if the cert's extKeyUsage extension is absent (DER
 * default: unrestricted), or present and contains purpose_oid among its
 * KeyPurposeIds. 0 if the extension is present but purpose_oid is absent,
 * or the extension is malformed. */
int quic_x509_eku_allows(quic_span tbs, quic_span purpose_oid);

#endif
