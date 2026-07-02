#include "crypto/pki/trust/castore/pathvalidate.h"

#include "crypto/pki/encoding/x509/basicconstraints.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/chainverify.h"

/* RFC 5280 4.1.2.4. View cert's issuer Name (header included). */
static int cert_issuer(quic_span cert, quic_span *dn) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_issuer(c.tbs, dn);
}

/* RFC 5280 4.1.2.6. View cert's subject Name (header included). */
static int cert_subject(quic_span cert, quic_span *dn) {
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

/* RFC 5280 6.1.4. An issuer cert must assert basicConstraints cA TRUE. */
static int cert_is_ca(quic_span cert) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_is_ca(c.tbs);
}

/* RFC 5280 6.1.3/6.1.4. One link: name binding, the parent is a CA, and the
 * parent signs the child. */
static int link_ok(quic_span child, quic_span parent) {
  if (!names_chain(child, parent)) return 0;
  if (!cert_is_ca(parent)) return 0;
  return quic_castore_verify_signed_by(child, parent);
}

/* RFC 5280 6.1.4. Find the registered anchor for issuer name and require it to
 * be a CA. */
static int find_ca_anchor(
    const quic_castore *s, quic_span iss, quic_span *root) {
  if (!quic_castore_find_by_subject(s, iss, root)) return 0;
  return cert_is_ca(*root);
}

/* RFC 5280 6.1. The tail must chain to a registered CA trust anchor: a root
 * whose subject equals the tail's issuer, and which signs the tail. */
static int tail_anchored(const quic_castore *s, quic_span tail) {
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
static int step_ok(const quic_span *certs, usz i) {
  return link_ok(certs[i], certs[i + 1]) && cert_pathlen_ok(certs[i + 1], i);
}

/* Every adjacent leaf-to-tail link binds and verifies. */
static int links_ok(const quic_span *certs, usz n) {
  for (usz i = 0; i + 1 < n; i++)
    if (!step_ok(certs, i)) return 0;
  return 1;
}

int quic_castore_validate_chain(
    const quic_castore *s, const quic_span *certs, usz n_certs) {
  if (n_certs < 1) return 0;
  if (!links_ok(certs, n_certs)) return 0;
  return tail_anchored(s, certs[n_certs - 1]);
}
