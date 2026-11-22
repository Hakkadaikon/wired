#include "castore_policy_golden.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "crypto/pki/trust/castore/pathvalidate_impl.h"
#include "test.h"

/* RFC 5280 6.1 / RFC 9618 5 policy processing over the chains of
 * castore_policy_golden.h, each mirroring the named NIST PKITS case. The
 * PKITS inputs (6.1.1 (c) user-initial-policy-set, (e)-(g) the three
 * initial-* flags) go through castore_policy_run; the default inputs also
 * go through castore_validate_chain, so the signatures and the production
 * wiring are exercised too. Certificates are listed leaf first. */

#define PTP_SPAN(der) wired_span_of(der, sizeof(der))
#define PTP_EXPL 1 /* initial-explicit-policy */
#define PTP_MAP 2  /* initial-policy-mapping-inhibit */
#define PTP_ANY 4  /* initial-any-policy-inhibit */

static const u8 ptp_p1[] = {0x2b, 0x03, 0x04, 0x01}; /* 1.3.3.4.1 */
static const u8 ptp_p2[] = {0x2b, 0x03, 0x04, 0x02}; /* 1.3.3.4.2 */

static castore_entry ptp_roots[1];

static x509_policy_set ptp_set(const u8* oid, usz n) {
  x509_policy_set s;
  s.n         = 1;
  s.truncated = 0;
  s.oid[0]    = wired_span_of(oid, n);
  return s;
}

/* castore_policy_run with user-initial-policy-set user (NULL: any-policy)
 * and the PTP_* initial flags; the final graph lands in *g. */
static int ptp_run(
    const wired_span*      certs,
    usz                    n,
    const x509_policy_set* user,
    int                    flags,
    x509_policy_graph*     g) {
  castore_policy_in in;
  in.user_set        = user;
  in.explicit_policy = flags & PTP_EXPL;
  in.map_inhibit     = (flags & PTP_MAP) != 0;
  in.any_inhibit     = (flags & PTP_ANY) != 0;
  return castore_policy_run(certs, n, &in, g);
}

/* castore_validate_chain under the ta anchor (no clock). */
static int ptp_validate(const wired_span* certs, usz n) {
  castore s;
  castore_init(&s, ptp_roots, 1);
  CHECK(castore_add(&s, PTP_SPAN(pol_ta_der)) == 1);
  return castore_validate_chain(&s, certs, n, 0);
}

static int ptp_has(const x509_policy_graph* g, const u8* oid, usz n) {
  return x509_policy_graph_has(g, 0, wired_span_of(oid, n));
}

/* PKITS 4.8.1 All Certificates Same Policy Test1: valid under any-policy
 * (authorities-constrained {P1}) and under {P1}; {P2} with
 * initial-explicit-policy is invalid. */
static void test_pkits_4_8_1_same_policy(void) {
  wired_span      c[2] = {PTP_SPAN(pol_ee_good_der), PTP_SPAN(pol_good_ca_der)};
  x509_policy_set p1 = ptp_set(ptp_p1, 4), p2 = ptp_set(ptp_p2, 4);
  x509_policy_graph g;
  CHECK(ptp_validate(c, 2) == 1);
  CHECK(ptp_run(c, 2, 0, 0, &g) == 1);
  CHECK(ptp_has(&g, ptp_p1, 4) == 1);
  CHECK(ptp_has(&g, ptp_p2, 4) == 0);
  CHECK(ptp_run(c, 2, &p1, PTP_EXPL, &g) == 1);
  CHECK(ptp_run(c, 2, &p2, PTP_EXPL, &g) == 0);
}

/* PKITS 4.8.2 All Certificates No Policies Test2: valid by default,
 * invalid once initial-explicit-policy is set. */
static void test_pkits_4_8_2_no_policies(void) {
  wired_span c[2] = {PTP_SPAN(pol_ee_no_pol_der), PTP_SPAN(pol_no_pol_ca_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(c, 2) == 1);
  CHECK(ptp_run(c, 2, 0, PTP_EXPL, &g) == 0);
}

/* PKITS 4.8.3 Different Policies Test3: P1 then P2 empties the graph; valid
 * by default, invalid with initial-explicit-policy. */
static void test_pkits_4_8_3_different_policies(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_p2sub_der), PTP_SPAN(pol_p2sub_der),
      PTP_SPAN(pol_good_ca_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(c, 3) == 1);
  CHECK(ptp_run(c, 3, 0, PTP_EXPL, &g) == 0);
}

/* PKITS 4.8.6 Overlapping Policies Test6: {P1,P2,P3} > {P1,P2} > {P1}
 * leaves {P1}: valid for {P1}, invalid for {P2} with explicit policy. */
static void test_pkits_4_8_6_overlapping(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_p12_der), PTP_SPAN(pol_p12sub_der),
      PTP_SPAN(pol_p123_ca_der)};
  x509_policy_set   p1 = ptp_set(ptp_p1, 4), p2 = ptp_set(ptp_p2, 4);
  x509_policy_graph g;
  CHECK(ptp_run(c, 3, &p1, PTP_EXPL, &g) == 1);
  CHECK(ptp_run(c, 3, &p2, PTP_EXPL, &g) == 0);
}

/* PKITS 4.8.11 All Certificates anyPolicy Test11: authorities-constrained
 * {anyPolicy}, so user {P1} gives user-constrained {P1} (RFC 9618 5.5
 * (g)(6)(ii)). */
static void test_pkits_4_8_11_all_any(void) {
  wired_span c[2] = {PTP_SPAN(pol_ee_any_any_der), PTP_SPAN(pol_any_ca_der)};
  x509_policy_set   p1 = ptp_set(ptp_p1, 4);
  x509_policy_graph g;
  CHECK(ptp_run(c, 2, &p1, PTP_EXPL, &g) == 1);
  CHECK(ptp_has(&g, x509_oid_any_policy, sizeof(x509_oid_any_policy)) == 1);
  CHECK(x509_policy_graph_has(&g, &p1, wired_span_of(ptp_p1, 4)) == 1);
}

/* PKITS 4.8.14 AnyPolicy Test14: anyPolicy CA, P1 end entity: valid for
 * {P1}, invalid for {P2} with explicit policy. */
static void test_pkits_4_8_14_any_policy(void) {
  wired_span c[2] = {PTP_SPAN(pol_ee_any_p1_der), PTP_SPAN(pol_any_ca_der)};
  x509_policy_set   p1 = ptp_set(ptp_p1, 4), p2 = ptp_set(ptp_p2, 4);
  x509_policy_graph g;
  CHECK(ptp_run(c, 2, &p1, PTP_EXPL, &g) == 1);
  CHECK(ptp_run(c, 2, &p2, PTP_EXPL, &g) == 0);
}

/* PKITS 4.10.1 Valid Policy Mapping Test1: P1 mapped to P2 by the CA, P2
 * end entity. Valid for {P1} (authorities-constrained {P1}), invalid for
 * {P2}, invalid with initial-policy-mapping-inhibit (both explicit). */
static void test_pkits_4_10_1_mapping(void) {
  wired_span c[2] = {PTP_SPAN(pol_ee_map12_der), PTP_SPAN(pol_map12_ca_der)};
  x509_policy_set   p1 = ptp_set(ptp_p1, 4), p2 = ptp_set(ptp_p2, 4);
  x509_policy_graph g;
  CHECK(ptp_validate(c, 2) == 1);
  CHECK(ptp_run(c, 2, &p1, PTP_EXPL, &g) == 1);
  CHECK(ptp_has(&g, ptp_p1, 4) == 1);
  CHECK(ptp_has(&g, ptp_p2, 4) == 0);
  CHECK(ptp_run(c, 2, &p2, PTP_EXPL, &g) == 0);
  CHECK(ptp_run(c, 2, 0, PTP_EXPL | PTP_MAP, &g) == 0);
}

/* PKITS 4.10.7 Invalid Mapping From anyPolicy Test7 / 4.10.8 Invalid
 * Mapping To anyPolicy Test8: RFC 5280 6.1.4 (a) rejects either. */
static void test_pkits_4_10_7_8_any_mapping(void) {
  wired_span from[2] = {
      PTP_SPAN(pol_ee_from_any_der), PTP_SPAN(pol_map_from_any_der)};
  wired_span to[2] = {
      PTP_SPAN(pol_ee_to_any_der), PTP_SPAN(pol_map_to_any_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(from, 2) == 0);
  CHECK(ptp_validate(to, 2) == 0);
  CHECK(ptp_run(from, 2, 0, 0, &g) == 0);
  CHECK(ptp_run(to, 2, 0, 0, &g) == 0);
}

/* PKITS 4.11.1 Invalid inhibitPolicyMapping Test1: inhibitPolicyMapping 0
 * deletes the mapped P1 node (6.1.4 (b)(2)) under requireExplicitPolicy
 * 0. */
static void test_pkits_4_11_1_inhibit_mapping(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_ipm0_der), PTP_SPAN(pol_ipm0sub_der),
      PTP_SPAN(pol_ipm0_ca_der)};
  CHECK(ptp_validate(c, 3) == 0);
}

/* PKITS 4.11.2 Valid inhibitPolicyMapping Test2: inhibitPolicyMapping 1
 * still lets the next CA map P1 to P2. */
static void test_pkits_4_11_2_inhibit_mapping_one(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_ipm1_der), PTP_SPAN(pol_ipm1sub_der),
      PTP_SPAN(pol_ipm1_ca_der)};
  CHECK(ptp_validate(c, 3) == 1);
}

/* PKITS 4.11.3 Invalid inhibitPolicyMapping Test3: with
 * inhibitPolicyMapping 1 a mapping two CAs further down is inhibited. */
static void test_pkits_4_11_3_inhibit_mapping_later(void) {
  wired_span c[4] = {
      PTP_SPAN(pol_ee_ipm1low_der), PTP_SPAN(pol_ipm1low_der),
      PTP_SPAN(pol_ipm1mid_der), PTP_SPAN(pol_ipm1_ca_der)};
  CHECK(ptp_validate(c, 4) == 0);
}

/* PKITS 4.12.1 Invalid inhibitAnyPolicy Test1 / 4.12.2 Valid
 * inhibitAnyPolicy Test2: after inhibitAnyPolicy 0 an anyPolicy end entity
 * adds nothing, but an explicit P1 still hangs off the CA's anyPolicy
 * node. */
static void test_pkits_4_12_1_2_inhibit_any(void) {
  wired_span any[2] = {
      PTP_SPAN(pol_ee_iap0_any_der), PTP_SPAN(pol_iap0_ca_der)};
  wired_span p1[2] = {PTP_SPAN(pol_ee_iap0_p1_der), PTP_SPAN(pol_iap0_ca_der)};
  CHECK(ptp_validate(any, 2) == 0);
  CHECK(ptp_validate(p1, 2) == 1);
}

/* PKITS 4.12.3 inhibitAnyPolicy Test3 / 4.12.4 Invalid inhibitAnyPolicy
 * Test4: inhibitAnyPolicy 1 still admits the sub-CA's anyPolicy (RFC 5280
 * 6.1.4 (h) decrements before (j) lowers), so a P1 end entity is valid
 * unless initial-any-policy-inhibit is set, and an anyPolicy end entity is
 * invalid. */
static void test_pkits_4_12_3_4_inhibit_any_one(void) {
  wired_span p1[3] = {
      PTP_SPAN(pol_ee_iap1_p1_der), PTP_SPAN(pol_iap1sub_der),
      PTP_SPAN(pol_iap1_ca_der)};
  wired_span any[3] = {
      PTP_SPAN(pol_ee_iap1_any_der), PTP_SPAN(pol_iap1sub_der),
      PTP_SPAN(pol_iap1_ca_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(p1, 3) == 1);
  CHECK(ptp_run(p1, 3, 0, PTP_ANY, &g) == 0);
  CHECK(ptp_validate(any, 3) == 0);
}

/* RFC 9618 3.2 Figure 1: nine CAs each mapping {P1,P2} onto {P1,P2} make a
 * 2^10-leaf RFC 5280 tree (OpenSSL 3.0.13 gives up on it); the graph keeps
 * two nodes per depth and validates, authorities-constrained {P1,P2}. */
static void test_policy_graph_figure1_linear(void) {
  wired_span        c[10] = {PTP_SPAN(pol_ee_dos_der), PTP_SPAN(pol_dos9_der),
                             PTP_SPAN(pol_dos8_der),   PTP_SPAN(pol_dos7_der),
                             PTP_SPAN(pol_dos6_der),   PTP_SPAN(pol_dos5_der),
                             PTP_SPAN(pol_dos4_der),   PTP_SPAN(pol_dos3_der),
                             PTP_SPAN(pol_dos2_der),   PTP_SPAN(pol_dos1_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(c, 10) == 1);
  CHECK(ptp_run(c, 10, 0, PTP_EXPL, &g) == 1);
  CHECK(ptp_has(&g, ptp_p1, 4) == 1);
  CHECK(ptp_has(&g, ptp_p2, 4) == 1);
}

/* Two CAs each hanging 16 fresh mappings off anyPolicy need 33 nodes at
 * depth 2, past X509_POLICY_NODES_MAX. RFC 5280 6.1.5 succeeds on
 * explicit_policy > 0 whatever the graph holds, so the default inputs
 * validate; with initial-explicit-policy the overflow is the bound's
 * defined failure. ovf1 alone (17 nodes) still fits; castore_policy_run
 * checks no issuer links, so eeOvf can stand in as its leaf. */
static void test_policy_graph_overflow_needs_explicit(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_ovf_der), PTP_SPAN(pol_ovf2_der), PTP_SPAN(pol_ovf1_der)};
  wired_span first[2] = {PTP_SPAN(pol_ee_ovf_der), PTP_SPAN(pol_ovf1_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(c, 3) == 1);
  CHECK(ptp_run(c, 3, 0, PTP_EXPL, &g) == 0);
  CHECK(ptp_run(first, 2, 0, PTP_EXPL, &g) == 1);
}

/* A CA listing nine policies (one past X509_CERT_POLICY_MAX): accepted
 * while explicit_policy > 0, rejected once an explicit policy is
 * required (the truncated set cannot be judged). */
static void test_policy_truncated_needs_explicit(void) {
  wired_span        c[2] = {PTP_SPAN(pol_ee_cp9_der), PTP_SPAN(pol_cp9_ca_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(c, 2) == 1);
  CHECK(ptp_run(c, 2, 0, PTP_EXPL, &g) == 0);
}

/* RFC 9618 5.3 (d)(2)(b): after inhibitAnyPolicy 0, the self-issued
 * iapsSelf (i < n) still processes its anyPolicy, so the P1 end entity
 * hangs off it under requireExplicitPolicy 0 (PKITS 4.12.7-4.12.10 test
 * the same rule). */
static void test_self_issued_any_policy(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_iaps_der), PTP_SPAN(pol_iaps_self_der),
      PTP_SPAN(pol_iaps_ca_der)};
  CHECK(ptp_validate(c, 3) == 1);
}

/* RFC 5280 6.1.4 (h): the self-issued rep2Self does not consume
 * requireExplicitPolicy 2, so explicit_policy is still 1 after the 6.1.5
 * (a) decrement and the policy-free path validates; with
 * initial-explicit-policy it does not. */
static void test_self_issued_not_counted(void) {
  wired_span c[3] = {
      PTP_SPAN(pol_ee_rep2_der), PTP_SPAN(pol_rep2_self_der),
      PTP_SPAN(pol_rep2_ca_der)};
  x509_policy_graph g;
  CHECK(ptp_validate(c, 3) == 1);
  CHECK(ptp_run(c, 3, 0, PTP_EXPL, &g) == 0);
}

void test_policytree_path(void) {
  test_pkits_4_8_1_same_policy();
  test_pkits_4_8_2_no_policies();
  test_pkits_4_8_3_different_policies();
  test_pkits_4_8_6_overlapping();
  test_pkits_4_8_11_all_any();
  test_pkits_4_8_14_any_policy();
  test_pkits_4_10_1_mapping();
  test_pkits_4_10_7_8_any_mapping();
  test_pkits_4_11_1_inhibit_mapping();
  test_pkits_4_11_2_inhibit_mapping_one();
  test_pkits_4_11_3_inhibit_mapping_later();
  test_pkits_4_12_1_2_inhibit_any();
  test_pkits_4_12_3_4_inhibit_any_one();
  test_policy_graph_figure1_linear();
  test_policy_graph_overflow_needs_explicit();
  test_policy_truncated_needs_explicit();
  test_self_issued_any_policy();
  test_self_issued_not_counted();
}
