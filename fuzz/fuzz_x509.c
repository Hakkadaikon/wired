/* libFuzzer harness for the X.509 certificate parser (RFC 5280 4.1) and the
 * TBSCertificate field extractor (RFC 5280 4.1.2). Hosted build only —
 * mirrors tests/run.c's unity-include style, but this file itself may use
 * the standard library since it lives outside src/.
 *
 * A certificate parser's job is to safely reject arbitrary bytes, so no
 * structured seed is needed: raw DER bytes drive both x509_parse and,
 * on success, the signatureAlgorithm allowlist (RFC 4055 RSASSA-PSS
 * parameters included), the tbsCertificate sub-parsers, the inner/outer
 * signatureAlgorithm comparison, extension lookup, and the RFC 5280
 * 4.2.1.5 policyMappings parser feeding the RFC 9618 policy graph. */
#include <stddef.h>
#include <stdint.h>

#include "crypto/pki/cert/tbscert/fields.c"
#include "crypto/pki/cert/tbscert/sigalg.c"
#include "crypto/pki/encoding/asn1/der.c"
#include "crypto/pki/encoding/asn1/derseq.c"
#include "crypto/pki/encoding/asn1/derval.c"
#include "crypto/pki/encoding/x509/certpolicies.c"
#include "crypto/pki/encoding/x509/policymap.c"
#include "crypto/pki/encoding/x509/policytree.c"
#include "crypto/pki/encoding/x509/policytree_map.c"
#include "crypto/pki/encoding/x509/policytree_node.c"
#include "crypto/pki/encoding/x509/sigalgoid.c"
#include "crypto/pki/encoding/x509/sigalgoid_pss.c"
#include "crypto/pki/encoding/x509/x509.c"
#include "crypto/pki/encoding/x509/x509_ext.c"
#include "crypto/pki/encoding/x509/x509_ext_crit.c"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wired_span cert = wired_span_of((const u8*)data, (usz)size);

  x509 x;
  if (!x509_parse(cert, &x)) {
    return 0;
  }

  /* Peer-controlled signatureAlgorithm (and RSASSA-PSS-params) bytes. */
  x509_sigalg a;
  x509_sigalg_lookup(x.sig_alg_oid, x.sig_alg_params, &a);

  /* tbsCertificate is well-formed enough to have been sliced out above;
   * fuzz its own structured sub-parsers on the same bytes. */
  tbscert tbs;
  if (tbscert_parse(x.tbs, &tbs)) {
    tbscert_sigalg_matches(&tbs, x.sig_alg_oid, x.sig_alg_params);
  }

  derseq c;
  x509_tbs_cursor(x.tbs, &c);

  /* RFC 5280 4.2.1.9 basicConstraints OID, walked regardless of whether it
   * is actually present — exercises the extensions-scan path too. */
  static const u8 basic_constraints_oid[] = {0x55, 0x1d, 0x13};
  wired_span      val;
  x509_find_ext(x.tbs, wired_span_of(basic_constraints_oid, 3), &val);

  /* The certificate's certificatePolicies / policyMappings folded into a
   * policy graph as two consecutive path certificates would be. The
   * input's last byte (inside the signature, so the committed raw-DER
   * corpus keeps working; the first byte is always 0x30) picks any_ok for
   * each fold, map_ok (0: the 6.1.4 (b)(3) deletion path) and whether the
   * certificate's own policies act as a user-initial-policy-set.
   * castore_policy_run itself is not linked here: it pulls in the whole
   * signature-verification closure of pathvalidate.c. */
  u8                sw = data[size - 1];
  x509_policy_graph g;
  x509_policy_set   user;
  x509_pm_unprocessed_critical(x.tbs);
  x509_policy_graph_init(&g);
  x509_policy_graph_fold(&g, x.tbs, sw & 1);
  x509_policy_graph_map(&g, x.tbs, (sw >> 1) & 1);
  x509_policy_graph_fold(&g, x.tbs, (sw >> 2) & 1);
  x509_policy_graph_nonempty(&g, 0);
  if (x509_cert_policies(x.tbs, &user)) {
    x509_policy_graph_nonempty(&g, (sw & 8) ? &user : 0);
    x509_policy_graph_has(&g, &user, x509_any_policy_oid());
  }

  return 0;
}
