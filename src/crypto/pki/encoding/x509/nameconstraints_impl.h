#ifndef CRYPTO_PKI_ENCODING_X509_NAMECONSTRAINTS_IMPL_H
#define CRYPTO_PKI_ENCODING_X509_NAMECONSTRAINTS_IMPL_H

/* Internal to the nameconstraints*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/dirstring.h"
#include "crypto/pki/encoding/x509/nameconstraints.h"
#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/x509.h"

/* RFC 5280 4.2.1.10. permittedSubtrees is [0], excludedSubtrees is [1],
 * both EXPLICIT (GeneralSubtrees is a SEQUENCE, a constructed type). */
#define NC_PERMITTED_TAG 0xa0
#define NC_EXCLUDED_TAG 0xa1
/* RFC 5280 4.2.1.6. The GeneralName CHOICE arms a GeneralSubtree base can
 * take that this SDK evaluates: dNSName is [2] IMPLICIT IA5String, URI is
 * [6] IMPLICIT IA5String, iPAddress is [7] IMPLICIT OCTET STRING, and
 * directoryName is [4] EXPLICIT Name (always EXPLICIT per X.690 31.2.7). */
#define NC_DNSNAME_TAG 0x82
#define NC_DIRECTORYNAME_TAG 0xa4
#define NC_URI_TAG 0x86
#define NC_IPADDR_TAG 0x87
/* RFC 5280 4.2.1.10. GeneralSubtree minimum is [0] IMPLICIT BaseDistance
 * (DEFAULT 0), maximum [1]. */
#define NC_MINIMUM_TAG 0x80

typedef int (*nc_matcher)(wired_span base, wired_span name);

int  x509_nc_locate(wired_span tbs, wired_span* val);
int  x509_nc_half(wired_span seq, u8 want_tag, wired_span* subtrees);
int  x509_dn_within_base(wired_span base, wired_span name);
int  x509_nc_dns_within(wired_span base, wired_span name);
int  x509_nc_ip_within(wired_span base, wired_span name);
void x509_typed_fold(
    wired_span sub,
    u8         want,
    wired_span name,
    nc_matcher m,
    int*       any,
    int*       covered);
int x509_typed_name_ok(wired_span seq, u8 want, wired_span name, nc_matcher m);
int x509_nc_too_many(wired_span seq);
int x509_nc_bounded(wired_span seq);
int x509_ip_bases_malformed(wired_span seq);
int x509_san_other_entry_ok(wired_span seq, u8 tag, wired_span e);

extern const u8 nc_oid_san[3];

#endif
