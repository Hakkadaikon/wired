#include "crypto/pki/trust/castore/castore.h"

#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"

void quic_castore_init(quic_castore* s, quic_castore_entry* roots, usz cap) {
  s->roots = roots;
  s->cap   = cap;
  s->count = 0;
}

/* A DER blob that parses as a certificate is acceptable to register. */
static int parses_as_cert(quic_span cert_der) {
  quic_x509 c;
  return quic_x509_parse(cert_der, &c);
}

int quic_castore_add(quic_castore* s, quic_span cert_der) {
  if (s->count >= s->cap) return 0;
  if (!parses_as_cert(cert_der)) return 0;
  s->roots[s->count] = cert_der;
  s->count++;
  return 1;
}

/* RFC 5280 6.1. 1 if the entry's subject Name equals issuer_dn. */
static int entry_subject_matches(quic_span entry, quic_span issuer_dn) {
  quic_x509 c;
  quic_span subj;
  if (!quic_x509_parse(entry, &c)) return 0;
  if (!quic_x509_subject(c.tbs, &subj)) return 0;
  return quic_x509_dn_equal(issuer_dn, subj);
}

int quic_castore_find_by_subject(
    const quic_castore* s, quic_span issuer_dn, quic_span* root) {
  for (usz i = 0; i < s->count; i++) {
    if (!entry_subject_matches(s->roots[i], issuer_dn)) continue;
    *root = s->roots[i];
    return 1;
  }
  return 0;
}
