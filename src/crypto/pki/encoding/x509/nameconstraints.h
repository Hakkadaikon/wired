#ifndef X509_NAMECONSTRAINTS_H
#define X509_NAMECONSTRAINTS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** Most GeneralSubtree entries (permittedSubtrees and excludedSubtrees
 * together) one nameConstraints extension may carry; an extension over the
 * bound rejects the child outright (fail closed). Every child name is
 * matched against every entry of its form, for every certificate below the
 * issuer, so the entry count multiplies verification work
 * (CVE-2024-34702 / CVE-2025-14831 class); with CASTORE_PATH_MAX_CERTS this
 * caps a path's name-constraint work at
 * CASTORE_PATH_MAX_CERTS^2 x names x this. 256 sits well above deployed
 * constrained intermediates (public CA program members carry at most a few
 * dozen entries). */
#define X509_NC_SUBTREES_MAX 256

/* RFC 5280 4.2.1.10 / 6.1.4 (g). cert's nameConstraints extension, applied to
 * subject: subject (a directoryName-form Name, header included, as returned
 * by x509_subject/x509_issuer) must fall within every permitted
 * directoryName subtree (if any are present) and outside every excluded
 * directoryName subtree. GeneralName forms other than directoryName ([0]-[3],
 * [5]-[8]) are not produced by this SDK's subject/SAN readers, so subtree
 * entries in those forms are ignored (RFC 5280 4.2.1.10 constrains only
 * names of the same type actually present in the certificate being
 * validated). A directoryName subtree matches by RDN prefix: base's RDN
 * sequence must equal, RDN for RDN under x509_dn_equal_ci's RFC 4518
 * caseIgnoreMatch rules (dirstring.h), the leading RDNs of subject's
 * (x509_dn_prefix_ci), so a subject differing from an excluded base only by
 * DirectoryString case cannot escape it. Returns 1 if subject is admitted by
 * cert's nameConstraints (or the extension is absent, or the extension does
 * not constrain directoryName), 0 if excluded, not covered by any permitted
 * subtree when at least one is present, or the extension is malformed (fail
 * closed). */
int x509_name_constraints_permit(wired_span cert_tbs, wired_span subject);

/* RFC 5280 4.2.1.10 / 6.1.4 (g). cert's nameConstraints extension, applied
 * to the whole child certificate: the child's subject Name against
 * directoryName subtrees (the x509_name_constraints_permit rule above), and
 * every child subjectAltName entry against the subtrees of its own
 * GeneralName form:
 *   - dNSName [2]: a base without a leading '.' covers the host equal to it
 *     and any subdomain (RFC 5280 4.2.1.10's "adding zero or more labels to
 *     the left"); a base with a leading '.' covers subdomains only; an empty
 *     base covers every DNS name. Comparison is ASCII case-insensitive; a
 *     '*' in a SAN entry is treated as a literal byte, so a wildcard entry
 *     is classified by its literal suffix. When the child carries no SAN
 *     dNSName entry at all, the dNSName subtrees are applied to its subject
 *     commonName if that CN is DNS-shaped (RFC 6125 6.4.4 / RFC 9525 CN-ID
 *     fallback practice, mirroring x509_san_matches' fallback so any name
 *     that function could accept is constrained here).
 *   - iPAddress [7]: base is address||mask, exactly twice the SAN address
 *     length (8 octets against an IPv4 SAN, 32 against an IPv6 SAN); it
 *     covers the SAN address iff (addr ^ san) & mask == 0. A base of the
 *     other family covers nothing (a permitted subtree then fails closed);
 *     a base of any length other than 8 or 32, in either half, is
 *     malformed and rejects the child outright (fail closed).
 *   - uniformResourceIdentifier [6]: URI matching is not implemented; a
 *     child presenting a URI SAN under an issuer whose nameConstraints
 *     carries any URI subtree (permitted or excluded) is rejected outright
 *     (fail closed).
 * Other GeneralName forms ([0]-[1], [3], [5], [8]) are not consumed by this
 * SDK and their subtrees are not evaluated. Returns 1 if the child is
 * admitted, 0 if any name is excluded, uncovered while a permitted subtree
 * of its form is present, or the child's subject/SAN is malformed (fail
 * closed). */
int x509_name_constraints_admit(wired_span issuer_tbs, wired_span child_tbs);

#endif
