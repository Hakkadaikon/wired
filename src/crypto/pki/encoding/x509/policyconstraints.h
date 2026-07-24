#ifndef QUIC_X509_POLICYCONSTRAINTS_H
#define QUIC_X509_POLICYCONSTRAINTS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* A SkipCerts value (RFC 5280 4.2.1.11) too large to ever be reached while
 * walking a certificate path of practical length; used as "no constraint". */
#define QUIC_X509_SKIPCERTS_NONE ((u64) - 1)
/* The extension is present but its SkipCerts encoding is malformed. Distinct
 * from QUIC_X509_SKIPCERTS_NONE so callers fail closed (reject) instead of
 * silently treating a malformed constraint as absent. */
#define QUIC_X509_SKIPCERTS_MALFORMED ((u64) - 2)

/* RFC 5280 4.2.1.11. PolicyConstraints ::= SEQUENCE {
 *   requireExplicitPolicy [0] SkipCerts OPTIONAL,
 *   inhibitPolicyMapping  [1] SkipCerts OPTIONAL }
 * View requireExplicitPolicy if the policyConstraints extension is present
 * and carries it. Returns QUIC_X509_SKIPCERTS_NONE if the extension is
 * absent or present without this field (both mean "unconstrained"), or
 * QUIC_X509_SKIPCERTS_MALFORMED if the extension is present but malformed. */
u64 quic_x509_require_explicit_policy(quic_span tbs);

/* RFC 5280 4.2.1.14. InhibitAnyPolicy ::= SkipCerts (a bare INTEGER
 * extnValue, not wrapped in a SEQUENCE). Returns QUIC_X509_SKIPCERTS_NONE if
 * absent, QUIC_X509_SKIPCERTS_MALFORMED if present but malformed. */
u64 quic_x509_inhibit_any_policy(quic_span tbs);

#endif
