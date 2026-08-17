#include "crypto/pki/trust/castore/castore.h"

#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"

void castore_init(castore* s, castore_entry* roots, usz cap) {
  s->roots = roots;
  s->cap   = cap;
  s->count = 0;
}

/* A DER blob that parses as a certificate is acceptable to register. */
static int parses_as_cert(wired_span cert_der) {
  x509 c;
  return x509_parse(cert_der, &c);
}

int castore_add(castore* s, wired_span cert_der) {
  if (s->count >= s->cap) return 0;
  if (!parses_as_cert(cert_der)) return 0;
  s->roots[s->count] = cert_der;
  s->count++;
  return 1;
}

/* RFC 5280 6.1. 1 if the entry's subject Name equals issuer_dn. */
static int entry_subject_matches(wired_span entry, wired_span issuer_dn) {
  x509       c;
  wired_span subj;
  if (!x509_parse(entry, &c)) return 0;
  if (!x509_subject(c.tbs, &subj)) return 0;
  return x509_dn_equal(issuer_dn, subj);
}

int castore_find_by_subject(
    const castore* s, wired_span issuer_dn, wired_span* root) {
  for (usz i = 0; i < s->count; i++) {
    if (!entry_subject_matches(s->roots[i], issuer_dn)) continue;
    *root = s->roots[i];
    return 1;
  }
  return 0;
}
