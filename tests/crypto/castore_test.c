#include "crypto/pki/trust/castore/castore.h"

#include "castore_golden.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

static quic_span cst_root_span(void) {
  return quic_span_of(quic_castore_root_der, sizeof(quic_castore_root_der));
}

/* Subject Name of the registered root (CN=Test Root CA). */
static void root_subject(quic_span *dn) {
  quic_x509 c;
  CHECK(quic_x509_parse(cst_root_span(), &c) == 1);
  CHECK(quic_x509_subject(c.tbs, dn) == 1);
}

/* Issuer Name of the leaf (equals the root's subject). */
static void leaf_issuer(quic_span *dn) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_castore_leaf_der, sizeof(quic_castore_leaf_der)),
          &c) == 1);
  CHECK(quic_x509_issuer(c.tbs, dn) == 1);
}

static void test_init_is_empty(void) {
  quic_castore       s;
  quic_castore_entry roots[2];
  quic_span          root, dn;
  quic_castore_init(&s, roots, 2);
  root_subject(&dn);
  CHECK(quic_castore_find_by_subject(&s, dn, &root) == 0);
}

static void test_add_then_find_by_leaf_issuer(void) {
  quic_castore       s;
  quic_castore_entry roots[2];
  quic_span          root, dn;
  quic_castore_init(&s, roots, 2);
  CHECK(quic_castore_add(&s, cst_root_span()) == 1);
  leaf_issuer(&dn);
  CHECK(quic_castore_find_by_subject(&s, dn, &root) == 1);
  CHECK(root.p == quic_castore_root_der);
  CHECK(root.n == sizeof(quic_castore_root_der));
}

/* A DN with no matching subject in the store is not found. */
static void test_find_unknown_subject_fails(void) {
  quic_castore       s;
  quic_castore_entry roots[2];
  quic_span          root, dn;
  quic_castore_init(&s, roots, 2);
  CHECK(quic_castore_add(&s, cst_root_span()) == 1);
  /* The leaf's own subject (CN=leaf.example) is no root subject. */
  {
    quic_x509 c;
    CHECK(
        quic_x509_parse(
            quic_span_of(quic_castore_leaf_der, sizeof(quic_castore_leaf_der)),
            &c) == 1);
    CHECK(quic_x509_subject(c.tbs, &dn) == 1);
  }
  CHECK(quic_castore_find_by_subject(&s, dn, &root) == 0);
}

static void test_add_rejects_malformed(void) {
  quic_castore       s;
  quic_castore_entry roots[2];
  const u8           junk[] = {0x00, 0x01, 0x02};
  quic_castore_init(&s, roots, 2);
  CHECK(quic_castore_add(&s, quic_span_of(junk, sizeof(junk))) == 0);
}

/* Capacity is the caller array's: cap 2 admits two roots, refuses a third. */
static void test_add_full_store_fails(void) {
  quic_castore       s;
  quic_castore_entry roots[2];
  quic_castore_init(&s, roots, 2);
  for (usz i = 0; i < 2; i++) CHECK(quic_castore_add(&s, cst_root_span()) == 1);
  CHECK(quic_castore_add(&s, cst_root_span()) == 0);
}

/* A real-trust-store-sized array (150 roots) registers and resolves. */
static void test_castore_cap(void) {
  quic_castore       s;
  quic_castore_entry roots[150];
  quic_span          root, dn;
  quic_castore_init(&s, roots, 150);
  for (usz i = 0; i < 150; i++)
    CHECK(quic_castore_add(&s, cst_root_span()) == 1);
  leaf_issuer(&dn);
  CHECK(quic_castore_find_by_subject(&s, dn, &root) == 1);
}

void test_castore(void) {
  test_init_is_empty();
  test_add_then_find_by_leaf_issuer();
  test_find_unknown_subject_fails();
  test_add_rejects_malformed();
  test_add_full_store_fails();
  test_castore_cap();
}
