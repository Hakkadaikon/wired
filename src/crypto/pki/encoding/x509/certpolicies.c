#include "crypto/pki/encoding/x509/certpolicies.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-certificatePolicies = 2.5.29.32 */
static const u8 oid_cert_policies[] = {0x55, 0x1d, 0x20};

/* RFC 5280 4.2.1.4. anyPolicy = { 2 5 29 32 0 }. */
const u8 quic_x509_oid_any_policy[4] = {0x55, 0x1d, 0x20, 0x00};

/* The certificatePolicies extnValue SEQUENCE, if present. */
static int cp_locate(wired_span tbs, wired_span* val) {
  wired_span raw;
  if (!quic_x509_find_ext(
          tbs, wired_span_of(oid_cert_policies, sizeof(oid_cert_policies)),
          &raw))
    return 0;
  return quic_der_seq(raw, val);
}

/* PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }. View the
 * leading OID. */
static int policy_info_id(wired_span info, wired_span* oid) {
  quic_derseq c;
  quic_derseq_init(&c, info);
  return quic_derseq_next_tagged(&c, QUIC_DER_OID, oid);
}

/* Append oid to *out if there is room; entries past the cap are dropped
 * (QUIC_X509_CERT_POLICY_MAX's header comment). */
static void policy_set_add(quic_x509_policy_set* out, wired_span oid) {
  if (out->n >= QUIC_X509_CERT_POLICY_MAX) return;
  out->oid[out->n] = oid;
  out->n++;
}

/* Fold one PolicyInformation element of the SEQUENCE into *out; a malformed
 * element (no leading OID) is skipped rather than failing the whole scan. */
static void cp_scan_one(wired_span info, quic_x509_policy_set* out) {
  wired_span oid;
  if (!policy_info_id(info, &oid)) return;
  policy_set_add(out, oid);
}

/* Scan the CertificatePolicies SEQUENCE OF PolicyInformation into *out. */
static void cp_scan(wired_span seq, quic_x509_policy_set* out) {
  quic_derseq c;
  u8          tag;
  wired_span  info;
  quic_derseq_init(&c, seq);
  while (quic_derseq_next(&c, &tag, &info)) cp_scan_one(info, out);
}

int quic_x509_cert_policies(wired_span tbs, quic_x509_policy_set* out) {
  wired_span seq;
  if (!cp_locate(tbs, &seq)) return 0;
  out->n = 0;
  cp_scan(seq, out);
  return 1;
}

int quic_x509_policy_set_has_any(const quic_x509_policy_set* set) {
  wired_span any =
      wired_span_of(quic_x509_oid_any_policy, sizeof(quic_x509_oid_any_policy));
  for (usz i = 0; i < set->n; i++)
    if (quic_der_oid_equal(set->oid[i], any)) return 1;
  return 0;
}
