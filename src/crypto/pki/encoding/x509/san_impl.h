#ifndef CRYPTO_PKI_ENCODING_X509_SAN_IMPL_H
#define CRYPTO_PKI_ENCODING_X509_SAN_IMPL_H

/* Internal to the san*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/x509.h"

#define SAN_DNSNAME_TAG 0x82
#define SAN_IPADDR_TAG 0x87
#define SAN_IPV4_LEN 4

/* RFC 5280 4.1. tbs elements before subject (version already skipped by
 * x509_tbs_cursor): serialNumber, signature, issuer, validity. */
#define SAN_SUBJECT_SKIP 4

int x509_entry_matches(wired_span e, wired_span host);
int san_ipv4_parse(wired_span host, u8 out[SAN_IPV4_LEN]);
int san_names(wired_span tbs, wired_span* names);
int x509_names_match(wired_span gn, wired_span host, int* found_dnsname);
int x509_ipv4_names_one(u8 tag, wired_span e, const u8 want[SAN_IPV4_LEN]);

extern const u8 oid_san[3];
extern const u8 san_oid_cn[3];

#endif
