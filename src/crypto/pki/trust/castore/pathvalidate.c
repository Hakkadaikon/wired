#include "crypto/pki/trust/castore/pathvalidate.h"

#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/chainverify.h"

/* RFC 5280 4.1.2.4. View cert's issuer Name (header included). */
static int cert_issuer(const u8 *cert, usz len, const u8 **dn, usz *dn_len) {
  quic_x509 c;
  if (!quic_x509_parse(cert, len, &c)) return 0;
  return quic_x509_issuer(c.tbs, c.tbs_len, dn, dn_len);
}

/* RFC 5280 4.1.2.6. View cert's subject Name (header included). */
static int cert_subject(const u8 *cert, usz len, const u8 **dn, usz *dn_len) {
  quic_x509 c;
  if (!quic_x509_parse(cert, len, &c)) return 0;
  return quic_x509_subject(c.tbs, c.tbs_len, dn, dn_len);
}

/* RFC 5280 6.1.3. certs[i]'s issuer equals certs[i+1]'s subject. */
static int names_chain(
    const u8 *child, usz child_len, const u8 *parent, usz parent_len) {
  const u8 *iss, *subj;
  usz       iss_len, subj_len;
  if (!cert_issuer(child, child_len, &iss, &iss_len)) return 0;
  if (!cert_subject(parent, parent_len, &subj, &subj_len)) return 0;
  return quic_x509_dn_equal(iss, iss_len, subj, subj_len);
}

/* RFC 5280 6.1.3. One link: name binding plus signature by the parent. */
static int link_ok(
    const u8 *child, usz child_len, const u8 *parent, usz parent_len) {
  if (!names_chain(child, child_len, parent, parent_len)) return 0;
  return quic_castore_verify_signed_by(child, child_len, parent, parent_len);
}

/* RFC 5280 6.1. The tail must chain to a registered trust anchor: a root whose
 * subject equals the tail's issuer, and which signs the tail. */
static int tail_anchored(const quic_castore *s, const u8 *tail, usz tail_len) {
  const u8 *iss, *root;
  usz       iss_len, root_len;
  if (!cert_issuer(tail, tail_len, &iss, &iss_len)) return 0;
  if (!quic_castore_find_by_subject(s, iss, iss_len, &root, &root_len))
    return 0;
  return quic_castore_verify_signed_by(tail, tail_len, root, root_len);
}

/* Every adjacent leaf-to-tail link binds and verifies. */
static int links_ok(const u8 *const *certs, const usz *lens, usz n) {
  for (usz i = 0; i + 1 < n; i++)
    if (!link_ok(certs[i], lens[i], certs[i + 1], lens[i + 1])) return 0;
  return 1;
}

int quic_castore_validate_chain(
    const quic_castore *s,
    const u8 *const    *certs,
    const usz          *cert_lens,
    usz                 n_certs) {
  if (n_certs < 1) return 0;
  if (!links_ok(certs, cert_lens, n_certs)) return 0;
  return tail_anchored(s, certs[n_certs - 1], cert_lens[n_certs - 1]);
}
