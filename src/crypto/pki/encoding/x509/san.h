#ifndef X509_SAN_H
#define X509_SAN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.6 / RFC 9525. 1 if the certificate covers hostname, 0
 * otherwise. A DNS name matches a subjectAltName dNSName (a leading "*."
 * wildcard covers one label only), or the subject commonName when the SAN
 * presents no DNS-ID, URI-ID or SRV-ID (RFC 6125 6.4.4). An IPv4 or IPv6
 * literal (no brackets) matches iPAddress entries only, never a dNSName
 * or the commonName. */
int x509_san_matches(wired_span tbs, wired_span hostname);

/* RFC 5280 4.1: locate and read the subject Name's commonName value out of
 * tbs (the value octets of the first commonName AttributeTypeAndValue found
 * across the RDNs). Returns 1 and sets *cn on success, 0 if the certificate
 * carries no commonName or the subject is malformed. */
int x509_subject_cn(wired_span tbs, wired_span* cn);

#endif
