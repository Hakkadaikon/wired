#ifndef QUIC_X509_NAMECONSTRAINTS_H
#define QUIC_X509_NAMECONSTRAINTS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.10 / 6.1.4 (g). cert's nameConstraints extension, applied to
 * subject: subject (a directoryName-form Name, header included, as returned
 * by x509_subject/x509_issuer) must fall within every permitted
 * directoryName subtree (if any are present) and outside every excluded
 * directoryName subtree. GeneralName forms other than directoryName ([0]-[3],
 * [5]-[8]) are not produced by this SDK's subject/SAN readers, so subtree
 * entries in those forms are ignored (RFC 5280 4.2.1.10 constrains only
 * names of the same type actually present in the certificate being
 * validated). A directoryName subtree matches by DER-prefix: base's encoded
 * Name must be a byte-for-byte prefix of subject's encoded Name (RFC 5280
 * 7.1's DN encoding is name-unique and this SDK re-encodes nothing, so a
 * literal DER Name is a stable byte string to prefix-match against, unlike
 * label-based domain constraints). Returns 1 if subject is admitted by
 * cert's nameConstraints (or the extension is absent, or the extension does
 * not constrain directoryName), 0 if excluded, not covered by any permitted
 * subtree when at least one is present, or the extension is malformed (fail
 * closed). */
int x509_name_constraints_permit(wired_span cert_tbs, wired_span subject);

#endif
