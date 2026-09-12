#ifndef X509_SAN_H
#define X509_SAN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.6 / RFC 6125. 1 if a subjectAltName dNSName matches the
 * hostname; 0 otherwise. A leading "*." wildcard matches one label only. */
int x509_san_matches(wired_span tbs, wired_span hostname);

/* RFC 5280 4.1: locate and read the subject Name's commonName value out of
 * tbs (the value octets of the first commonName AttributeTypeAndValue found
 * across the RDNs). Returns 1 and sets *cn on success, 0 if the certificate
 * carries no commonName or the subject is malformed. */
int x509_subject_cn(wired_span tbs, wired_span* cn);

#endif
