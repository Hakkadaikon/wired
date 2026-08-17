#ifndef X509_CERTPOLICIES_H
#define X509_CERTPOLICIES_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.4. Up to this many PolicyInformation policyIdentifier OIDs
 * are read out of one certificate's certificatePolicies extension; a
 * certificate listing more is truncated to this cap (RFC 5280 does not bound
 * the count, but real-world certificates list at most a handful). */
#define X509_CERT_POLICY_MAX 8

/** A fixed-capacity set of policy OID views into a certificate's tbs buffer
 * (no copying, no allocation). */
typedef struct {
  wired_span oid[X509_CERT_POLICY_MAX];
  usz        n;
} x509_policy_set;

/* RFC 5280 4.2.1.4. anyPolicy = 2.5.29.32.0. */
extern const u8 x509_oid_any_policy[4];

/* RFC 5280 4.2.1.4. 1 if tbs carries a certificatePolicies extension, else 0.
 * On 1, *out lists its policyIdentifier OIDs (capped at
 * X509_CERT_POLICY_MAX; malformed PolicyInformation entries are
 * skipped rather than aborting the whole extension, matching the "SHOULD NOT
 * duplicate" tolerance of 4.2.1.4). *out is untouched on return 0. */
int x509_cert_policies(wired_span tbs, x509_policy_set* out);

/* 1 if set contains the anyPolicy OID. */
int x509_policy_set_has_any(const x509_policy_set* set);

#endif
