#include "crypto/pki/trust/castore/pathvalidate.h"

#include "crypto/pki/encoding/x509/basicconstraints.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/eku.h"
#include "crypto/pki/encoding/x509/keyusage.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/chainverify.h"

/* RFC 5280 4.2.1.12. The leaf (certs[0], the end-entity server certificate)
 * must permit id-kp-serverAuth: extKeyUsage absent is unrestricted, present
 * without serverAuth rejects. The only caller of validate_chain in this SDK
 * is server-certificate verification (see pathvalidate.h). */
static int leaf_allows_server_auth(quic_span leaf) {
  quic_x509 c;
  if (!quic_x509_parse(leaf, &c)) return 0;
  return quic_x509_eku_allows(
      c.tbs, quic_span_of(
                 quic_x509_oid_server_auth, sizeof(quic_x509_oid_server_auth)));
}

/* RFC 5280 4.1.2.4. View cert's issuer Name (header included). */
static int cert_issuer(quic_span cert, quic_span* dn) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_issuer(c.tbs, dn);
}

/* RFC 5280 4.1.2.6. View cert's subject Name (header included). */
static int cert_subject(quic_span cert, quic_span* dn) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_subject(c.tbs, dn);
}

/* RFC 5280 6.1.3. certs[i]'s issuer equals certs[i+1]'s subject. */
static int names_chain(quic_span child, quic_span parent) {
  quic_span iss, subj;
  if (!cert_issuer(child, &iss)) return 0;
  if (!cert_subject(parent, &subj)) return 0;
  return quic_x509_dn_equal(iss, subj);
}

/* RFC 5280 4.2. cert carries no unrecognized critical extension. */
static int cert_known_critical_ok(quic_span cert) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return !quic_x509_has_unknown_critical(c.tbs);
}

/* Every certificate in the path (leaf through tail) is free of unrecognized
 * critical extensions (RFC 5280 4.2 MUST reject). */
static int no_unknown_critical(const quic_span* certs, usz n_certs) {
  for (usz i = 0; i < n_certs; i++)
    if (!cert_known_critical_ok(certs[i])) return 0;
  return 1;
}

/* RFC 5280 4.2.1.3/6.1.4. An issuer cert is a CA and, if keyUsage is
 * present, asserts keyCertSign (absent keyUsage is unconstrained). */
static int cert_can_issue(quic_span cert) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  if (!quic_x509_is_ca(c.tbs)) return 0;
  return quic_x509_can_sign_certs(c.tbs);
}

/* RFC 5280 6.1.3/6.1.4. One link: name binding, the parent may issue certs,
 * and the parent signs the child. */
static int link_ok(quic_span child, quic_span parent) {
  if (!names_chain(child, parent)) return 0;
  if (!cert_can_issue(parent)) return 0;
  return quic_castore_verify_signed_by(child, parent);
}

/* RFC 5280 6.1.4. Find the registered anchor for issuer name and require it
 * to be a CA permitted to issue certs. */
static int find_ca_anchor(
    const quic_castore* s, quic_span iss, quic_span* root) {
  if (!quic_castore_find_by_subject(s, iss, root)) return 0;
  return cert_can_issue(*root);
}

/* RFC 5280 6.1. The tail must chain to a registered CA trust anchor: a root
 * whose subject equals the tail's issuer, and which signs the tail. */
static int tail_anchored(const quic_castore* s, quic_span tail) {
  quic_span iss, root;
  if (!cert_issuer(tail, &iss)) return 0;
  if (!find_ca_anchor(s, iss, &root)) return 0;
  return quic_castore_verify_signed_by(tail, root);
}

/* RFC 5280 6.1.4 (m). The issuer's pathLenConstraint must admit the number of
 * intermediate certs below it (the leaf is not counted). */
static int cert_pathlen_ok(quic_span cert, usz below) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_pathlen_allows(c.tbs, below);
}

/* One step: the link verifies and the issuer certs[i+1] admits the i
 * intermediates (certs[1..i]) between it and the leaf. */
static int step_ok(const quic_span* certs, usz i) {
  return link_ok(certs[i], certs[i + 1]) && cert_pathlen_ok(certs[i + 1], i);
}

/* Every adjacent leaf-to-tail link binds and verifies. */
static int links_ok(const quic_span* certs, usz n) {
  for (usz i = 0; i + 1 < n; i++)
    if (!step_ok(certs, i)) return 0;
  return 1;
}

/* RFC 5280 6.1: certs[i] does not byte-equal any earlier certificate in the
 * path. */
static int cert_seen_before(const quic_span* certs, usz i) {
  for (usz j = 0; j < i; j++)
    if (quic_x509_dn_equal(certs[i], certs[j])) return 1;
  return 0;
}

/* No certificate in the path appears more than once. */
static int no_duplicate_certs(const quic_span* certs, usz n_certs) {
  for (usz i = 0; i < n_certs; i++)
    if (cert_seen_before(certs, i)) return 0;
  return 1;
}

/* Every certificate is hygienic: no unknown-critical extension, and it does
 * not repeat an earlier certificate in the path. */
static int certs_hygienic(const quic_span* certs, usz n_certs) {
  if (!no_unknown_critical(certs, n_certs)) return 0;
  return no_duplicate_certs(certs, n_certs);
}

/* The leaf's purpose, per-certificate hygiene, and every adjacent link
 * verify. */
static int path_ok(const quic_span* certs, usz n_certs) {
  if (!leaf_allows_server_auth(certs[0])) return 0;
  if (!certs_hygienic(certs, n_certs)) return 0;
  return links_ok(certs, n_certs);
}

int quic_castore_validate_chain(
    const quic_castore* s, const quic_span* certs, usz n_certs) {
  if (n_certs < 1) return 0;
  if (!path_ok(certs, n_certs)) return 0;
  return tail_anchored(s, certs[n_certs - 1]);
}
