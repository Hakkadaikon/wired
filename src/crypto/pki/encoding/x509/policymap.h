#ifndef X509_POLICYMAP_H
#define X509_POLICYMAP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 5280 4.2.1.5 bounds neither the count of mappings nor the size of a
 * certificate; this SDK keeps at most this many pairs from one certificate
 * and marks one carrying more truncated, which overflows the policy graph
 * (policytree.h: the per-certificate input that drives its growth stays
 * bounded, RFC 9618 6). */
#define X509_POLICY_MAPS_MAX 16

/** One certificate's policyMappings: idp[k] (issuerDomainPolicy) is
 * mapped to sdp[k] (subjectDomainPolicy). Views into the tbs buffer.
 * truncated is 1 when pairs past the cap were dropped. */
typedef struct {
  wired_span idp[X509_POLICY_MAPS_MAX];
  wired_span sdp[X509_POLICY_MAPS_MAX];
  usz        n;
  int        truncated;
} x509_policy_maps;

/* RFC 5280 4.2.1.5. PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 * issuerDomainPolicy CertPolicyId, subjectDomainPolicy CertPolicyId }.
 * Returns 0 if tbs has no policyMappings (m->n = 0), 1 if it parsed into
 * *m (pairs past X509_POLICY_MAPS_MAX dropped, m->truncated set), -1 if it
 * is malformed (not exactly that shape, empty) or maps to or from
 * anyPolicy ("Policies MUST
 * NOT be mapped either to or from the special value anyPolicy", checked by
 * 6.1.4 (a)). */
int x509_policy_mappings(wired_span tbs, x509_policy_maps* m);

/* RFC 5280 4.2: 1 if tbs's policyMappings is critical and
 * x509_policy_mappings rejects it, else 0. */
int x509_pm_unprocessed_critical(wired_span tbs);

#endif
