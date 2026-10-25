#include "castore_path_golden.h"
#include "castore_pc_golden.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
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

void test_pathvalidate_path(void) {
  test_path_validity_in_window_ok();
  test_path_intermediate_expired_rejects();
  test_path_anchor_expired_rejects();
  test_require_explicit_policy_root_omitted_rejects();
  test_require_explicit_policy_root_omitted_ok();
}
