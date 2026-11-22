#ifndef X509_POLICYCONSTRAINTS_H
#define X509_POLICYCONSTRAINTS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* A SkipCerts value (RFC 5280 4.2.1.11) too large to ever be reached while
 * walking a certificate path of practical length; used as "no constraint". */
#define X509_SKIPCERTS_NONE ((u64) - 1)
/* The extension is present but its SkipCerts encoding is malformed. Distinct
 * from X509_SKIPCERTS_NONE so callers fail closed (reject) instead of
 * silently treating a malformed constraint as absent. */
#define X509_SKIPCERTS_MALFORMED ((u64) - 2)

/* RFC 5280 4.2.1.11. PolicyConstraints ::= SEQUENCE {
 *   requireExplicitPolicy [0] SkipCerts OPTIONAL,
 *   inhibitPolicyMapping  [1] SkipCerts OPTIONAL }
 * View requireExplicitPolicy if the policyConstraints extension is present
 * and carries it. Returns X509_SKIPCERTS_NONE if the extension is
 * absent or present without this field (both mean "unconstrained"), or
 * X509_SKIPCERTS_MALFORMED if the extension is present but malformed. */
u64 x509_require_explicit_policy(wired_span tbs);

/* RFC 5280 4.2.1.11. inhibitPolicyMapping, with the same return values
 * as x509_require_explicit_policy. */
u64 x509_inhibit_policy_mapping(wired_span tbs);

/* RFC 5280 4.2: 1 if tbs's policyConstraints is critical but malformed
 * (not one SEQUENCE exactly filling extnValue, elements not exactly
 * filling it, [1] before [0], a field repeated, or a bad SkipCerts); 0
 * otherwise. */
int x509_pc_unprocessed_critical(wired_span tbs);

/* RFC 5280 4.2.1.14. InhibitAnyPolicy ::= SkipCerts (a bare INTEGER
 * extnValue, not wrapped in a SEQUENCE). Returns X509_SKIPCERTS_NONE if
 * absent, X509_SKIPCERTS_MALFORMED if present but malformed. */
u64 x509_inhibit_any_policy(wired_span tbs);

#endif
