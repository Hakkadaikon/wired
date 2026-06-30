#include "crypto/pki/trust/castore/castore.h"

#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"

void quic_castore_init(quic_castore *s) { s->count = 0; }

/* A DER blob that parses as a certificate is acceptable to register. */
static int parses_as_cert(const u8 *cert_der, usz len) {
  quic_x509 c;
  return quic_x509_parse(cert_der, len, &c);
}

int quic_castore_add(quic_castore *s, const u8 *cert_der, usz len) {
  if (s->count >= QUIC_CASTORE_MAX) return 0;
  if (!parses_as_cert(cert_der, len)) return 0;
  s->roots[s->count].cert = cert_der;
  s->roots[s->count].len  = len;
  s->count++;
  return 1;
}

/* RFC 5280 6.1. 1 if the entry's subject Name equals issuer_dn. */
static int entry_subject_matches(
    const quic_castore_entry *e, const u8 *issuer_dn, usz dn_len) {
  quic_x509 c;
  const u8 *subj;
  usz       subj_len;
  if (!quic_x509_parse(e->cert, e->len, &c)) return 0;
  if (!quic_x509_subject(c.tbs, c.tbs_len, &subj, &subj_len)) return 0;
  return quic_x509_dn_equal(issuer_dn, dn_len, subj, subj_len);
}

int quic_castore_find_by_subject(
    const quic_castore *s,
    const u8           *issuer_dn,
    usz                 dn_len,
    const u8          **root,
    usz                *root_len) {
  for (usz i = 0; i < s->count; i++) {
    if (!entry_subject_matches(&s->roots[i], issuer_dn, dn_len)) continue;
    *root     = s->roots[i].cert;
    *root_len = s->roots[i].len;
    return 1;
  }
  return 0;
}
