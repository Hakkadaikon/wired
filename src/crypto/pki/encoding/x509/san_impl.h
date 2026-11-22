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
/* RFC 5280 4.2.1.6: otherName is [0] IMPLICIT (constructed), URI is [6]
 * IMPLICIT IA5String. */
#define SAN_OTHERNAME_TAG 0xa0
#define SAN_URI_TAG 0x86
#define SAN_IPV4_LEN 4
#define SAN_IPV6_LEN 16

/* RFC 5280 4.1. tbs elements before subject (version already skipped by
 * x509_tbs_cursor): serialNumber, signature, issuer, validity. */
#define SAN_SUBJECT_SKIP 4

int x509_entry_matches(wired_span e, wired_span host);
int san_ipv4_parse(wired_span host, u8 out[SAN_IPV4_LEN]);
int san_ipv6_parse(wired_span host, u8 out[SAN_IPV6_LEN]);
int san_ipv6_shaped(wired_span host);
int san6_list(wired_span s, u8* out, usz* n, int v4);
int san_names(wired_span tbs, wired_span* names);
int x509_names_match(wired_span gn, wired_span host, int* found_id);
int san_presented_id(u8 tag, wired_span e);
int x509_ip_names_one(u8 tag, wired_span e, wired_span want);

extern const u8 oid_san[3];
extern const u8 san_oid_cn[3];

#endif
