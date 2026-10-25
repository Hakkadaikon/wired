#include "castore_path_golden.h"
#include "castore_pc_golden.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "crypto/pki/trust/castore/pathvalidate_impl.h"
#include "test.h"

/* RFC 5280 6.1 path-validation checks driven through castore_validate_chain
 * over the OpenSSL-generated fixtures in castore_path_golden.h. */

#define PKP_SPAN(der) wired_span_of(der, sizeof(der))
/* Inside every fixture window (all were issued 2026-10-25). */
#define PKP_NOW_IN 20261101000000ULL
/* After the 30-day vint / sroot windows, inside every 20-year one. */
#define PKP_NOW_2030 20300101000000ULL

static castore_entry pkp_roots[2];

static void pkp_store(castore* s, wired_span root) {
  castore_init(s, pkp_roots, 2);
  CHECK(castore_add(s, root) == 1);
}

/* RFC 5280 6.1.3 (a)(2): [vleaf, vint] under root, all windows open. */
static void test_path_validity_in_window_ok(void) {
  castore    s;
  wired_span certs[2] = {PKP_SPAN(pkp_vleaf_der), PKP_SPAN(pkp_vint_der)};
  pkp_store(&s, PKP_SPAN(pkp_root_der));
  CHECK(castore_validate_chain(&s, certs, 2, PKP_NOW_IN) == 1);
}

/* RFC 5280 6.1.3 (a)(2): the leaf is in window but the intermediate vint
 * expired -- the path is rejected (openssl: error 10 at depth 1). */
static void test_path_intermediate_expired_rejects(void) {
  castore    s;
  wired_span certs[2] = {PKP_SPAN(pkp_vleaf_der), PKP_SPAN(pkp_vint_der)};
  pkp_store(&s, PKP_SPAN(pkp_root_der));
  CHECK(castore_validate_chain(&s, certs, 2, PKP_NOW_2030) == 0);
  CHECK(castore_validate_chain(&s, certs, 2, 0) == 1);
}

/* The matched store anchor sroot expired while the presented [sleaf, sint]
 * are in window: rejected (openssl: error 10 at depth 2). */
static void test_path_anchor_expired_rejects(void) {
  castore    s;
  wired_span certs[2] = {PKP_SPAN(pkp_sleaf_der), PKP_SPAN(pkp_sint_der)};
  pkp_store(&s, PKP_SPAN(pkp_sroot_der));
  CHECK(castore_validate_chain(&s, certs, 2, PKP_NOW_IN) == 1);
  CHECK(castore_validate_chain(&s, certs, 2, PKP_NOW_2030) == 0);
}

/* RFC 5280 6.1.3 (d)/6.1.4 (i)/6.1.5 (g): the root is NOT sent, so mid2
 * (requireExplicitPolicy:0, policy_x) is certificate 1 and must be walked:
 * leaf4's disjoint policy_y empties the tree and the path is rejected. */
static void test_require_explicit_policy_root_omitted_rejects(void) {
  castore    s;
  wired_span certs[2] = {
      PKP_SPAN(castore_pc_leaf4_der), PKP_SPAN(castore_pc_mid2_der)};
  pkp_store(&s, PKP_SPAN(castore_pc_root_der));
  CHECK(castore_validate_chain(&s, certs, 2, 0) == 0);
}

/* Same root-omitted shape with leaf3's matching policy_x: accepted. */
static void test_require_explicit_policy_root_omitted_ok(void) {
  castore    s;
  wired_span certs[2] = {
      PKP_SPAN(castore_pc_leaf3_der), PKP_SPAN(castore_pc_mid2_der)};
  pkp_store(&s, PKP_SPAN(castore_pc_root_der));
  CHECK(castore_validate_chain(&s, certs, 2, 0) == 1);
}

/* RFC 5280 6.1.3 (b)/(c): ncmid permits only dirName O=Good; the
 * self-issued intermediate ncmid2 (CN=Path NC Mid, not the final
 * certificate) lies outside it but is skipped, and ncleaf's subject
 * O=Good/CN=leaf.example is inside: accepted (openssl verify: OK). */
static void test_nc_self_issued_intermediate_skipped(void) {
  castore    s;
  wired_span certs[3] = {
      PKP_SPAN(pkp_ncleaf_der), PKP_SPAN(pkp_ncmid2_der),
      PKP_SPAN(pkp_ncmid_der)};
  pkp_store(&s, PKP_SPAN(pkp_root_der));
  CHECK(castore_validate_chain(&s, certs, 3, PKP_NOW_IN) == 1);
}

/* RFC 5280 7.1 caseIgnoreMatch: cleaf's issuer is spelled CN=PATH CASE
 * ROOT, croot's subject CN=Path Case Root. The anchor lookup (root not
 * sent) and the issuer/subject link (root sent) both match (openssl
 * verify: OK). */
static void test_path_issuer_case_differs_ok(void) {
  castore    s;
  wired_span certs[2] = {PKP_SPAN(pkp_cleaf_der), PKP_SPAN(pkp_croot_der)};
  pkp_store(&s, PKP_SPAN(pkp_croot_der));
  CHECK(castore_validate_chain(&s, certs, 1, PKP_NOW_IN) == 1);
  CHECK(castore_validate_chain(&s, certs, 2, PKP_NOW_IN) == 1);
}

/* RFC 5280 6.1 "self-issued": subject and issuer DNs match under 7.1 rules,
 * so cself (CN=Path Case Root issued by CN=PATH CASE ROOT) is self-issued;
 * cleaf (CN=leaf.example) is not. */
static void test_self_issued_case_insensitive(void) {
  CHECK(castore_cert_self_issued(PKP_SPAN(pkp_cself_der)) == 1);
  CHECK(castore_cert_self_issued(PKP_SPAN(pkp_cleaf_der)) == 0);
}

/* RFC 5280 4.2.1.12 + RFC 8446 4.4.2.2: the leaf is used to sign
 * CertificateVerify, so a keyUsage without digitalSignature (kuenc:
 * keyEncipherment only) is rejected even with serverAuth EKU; kuds
 * (digitalSignature + keyEncipherment) is accepted. */
static void test_leaf_ku_without_digital_signature_rejects(void) {
  castore    s;
  wired_span bad[1] = {PKP_SPAN(pkp_kuenc_der)};
  wired_span ok[1]  = {PKP_SPAN(pkp_kuds_der)};
  pkp_store(&s, PKP_SPAN(pkp_root_der));
  CHECK(castore_validate_chain(&s, bad, 1, PKP_NOW_IN) == 0);
  CHECK(castore_validate_chain(&s, ok, 1, PKP_NOW_IN) == 1);
}

/* A lone self-signed CA registered as its own anchor: the path is just the
 * certificate, so only its extension checks can reject it. */
static int pkp_lone(wired_span cert) {
  castore    s;
  wired_span certs[1] = {cert};
  pkp_store(&s, cert);
  return castore_validate_chain(&s, certs, 1, PKP_NOW_IN);
}

/* RFC 5280 4.2.1.10: a critical nameConstraints whose GeneralSubtree
 * carries minimum 1 or a maximum is rejected (this SDK does not process
 * them); the same subtree in a non-critical extension is ignorable. */
static void test_critical_nc_min_max_rejects(void) {
  CHECK(pkp_lone(PKP_SPAN(pkp_ncmin_der)) == 0);
  CHECK(pkp_lone(PKP_SPAN(pkp_ncmax_der)) == 0);
  CHECK(pkp_lone(PKP_SPAN(pkp_ncminnc_der)) == 1);
}

/* RFC 5280 4.2.1.11: policy mapping is not supported, so a critical
 * policyConstraints carrying inhibitPolicyMapping is rejected; one with
 * only requireExplicitPolicy is processed and accepted. */
static void test_critical_pc_inhibit_mapping_rejects(void) {
  CHECK(pkp_lone(PKP_SPAN(pkp_pcipm_der)) == 0);
  CHECK(pkp_lone(PKP_SPAN(pkp_pcrep_der)) == 1);
}

/* RFC 5280 4.2.1.4: policy qualifiers are not interpreted, so a critical
 * certificatePolicies carrying one (a CPS pointer) is rejected; the same
 * extension non-critical is accepted. */
static void test_critical_cp_qualifier_rejects(void) {
  CHECK(pkp_lone(PKP_SPAN(pkp_cpq_der)) == 0);
  CHECK(pkp_lone(PKP_SPAN(pkp_cpqnc_der)) == 1);
}

void test_pathvalidate_path(void) {
  test_path_validity_in_window_ok();
  test_path_intermediate_expired_rejects();
  test_path_anchor_expired_rejects();
  test_require_explicit_policy_root_omitted_rejects();
  test_require_explicit_policy_root_omitted_ok();
  test_nc_self_issued_intermediate_skipped();
  test_path_issuer_case_differs_ok();
  test_self_issued_case_insensitive();
  test_leaf_ku_without_digital_signature_rejects();
  test_critical_nc_min_max_rejects();
  test_critical_pc_inhibit_mapping_rejects();
  test_critical_cp_qualifier_rejects();
}
