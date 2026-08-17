#ifndef X509_DIRSTRING_H
#define X509_DIRSTRING_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.1.2.4 / RFC 4518. DirectoryString string preparation +
 * caseIgnoreMatch, scoped to what a DN comparison needs:
 *   - ASCII case folding (RFC 4518 2.3's Map step, ASCII subset only --
 *     this SDK has no Unicode case-folding table, so this is not the full
 *     RFC 4518 algorithm for non-ASCII text);
 *   - leading/trailing whitespace trimmed and internal whitespace runs
 *     collapsed to one space (RFC 4518 2.6.1 Insignificant Space Handling,
 *     ASCII space only).
 * A DirectoryString value byte containing any octet >= 0x80 (part of a
 * multi-byte UTF-8/BMPString/UniversalString/TeletexString encoding this
 * SDK does not decode) makes the two values compare unequal unless they are
 * byte-identical -- this fails closed (rejects a match) rather than risk
 * mis-folding a multi-byte sequence into a false match. */

/* 1 if the two DirectoryString content octets (tag+length stripped, e.g. the
 * value of a PrintableString/UTF8String/IA5String/TeletexString/BMPString/
 * UniversalString TLV) are equal under the above rules; 0 otherwise. */
int x509_dirstring_ci_equal(wired_span a, wired_span b);

/* RFC 5280 7.1. 1 if Name a and Name b (each the Name SEQUENCE's TLV,
 * header included, as returned by x509_issuer/x509_subject) are
 * equal: same number of RDNs, each RDN pair has the same number of
 * AttributeTypeAndValue elements IN THE SAME ORDER, each pair's type OID is
 * byte-equal, and each pair's value is dirstring-ci-equal. RDN element
 * order within a SET has no defined canonical order in DER, so an RDN
 * containing multiple AttributeTypeAndValues emitted in a different
 * relative order by the two certificates compares unequal here (fails
 * closed towards the stricter byte-equal behavior of x509_dn_equal for
 * that rare multi-valued-RDN case, rather than implement full
 * unordered-SET matching). Returns 0 if either Name is malformed. */
int x509_dn_equal_ci(wired_span a, wired_span b);

#endif
