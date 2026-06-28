#ifndef QUIC_X509_SAN_H
#define QUIC_X509_SAN_H

#include "sys/syscall.h"

/* RFC 5280 4.2.1.6 / RFC 6125. 1 if a subjectAltName dNSName matches the
 * hostname; 0 otherwise. A leading "*." wildcard matches one label only. */
int quic_x509_san_matches(const u8 *tbs, usz tbs_len,
                          const u8 *hostname, usz host_len);

#endif
