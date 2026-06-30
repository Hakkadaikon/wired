#include "crypto/pki/trust/castore/castore.h"

#include "castore_golden.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* Subject Name of the registered root (CN=Test Root CA). */
static void root_subject(const u8 **dn, usz *dn_len) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_castore_root_der, sizeof(quic_castore_root_der), &c) == 1);
  CHECK(quic_x509_subject(c.tbs, c.tbs_len, dn, dn_len) == 1);
}

/* Issuer Name of the leaf (equals the root's subject). */
static void leaf_issuer(const u8 **dn, usz *dn_len) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_castore_leaf_der, sizeof(quic_castore_leaf_der), &c) == 1);
  CHECK(quic_x509_issuer(c.tbs, c.tbs_len, dn, dn_len) == 1);
}

static void test_init_is_empty(void) {
  quic_castore s;
  const u8    *root, *dn;
  usz          root_len, dn_len;
  quic_castore_init(&s);
  root_subject(&dn, &dn_len);
  CHECK(quic_castore_find_by_subject(&s, dn, dn_len, &root, &root_len) == 0);
}

static void test_add_then_find_by_leaf_issuer(void) {
  quic_castore s;
  const u8    *root, *dn;
  usz          root_len, dn_len;
  quic_castore_init(&s);
  CHECK(
      quic_castore_add(
          &s, quic_castore_root_der, sizeof(quic_castore_root_der)) == 1);
  leaf_issuer(&dn, &dn_len);
  CHECK(quic_castore_find_by_subject(&s, dn, dn_len, &root, &root_len) == 1);
  CHECK(root == quic_castore_root_der);
  CHECK(root_len == sizeof(quic_castore_root_der));
}

/* A DN with no matching subject in the store is not found. */
static void test_find_unknown_subject_fails(void) {
  quic_castore s;
  const u8    *root, *dn;
  usz          root_len, dn_len;
  quic_castore_init(&s);
  CHECK(
      quic_castore_add(
          &s, quic_castore_root_der, sizeof(quic_castore_root_der)) == 1);
  /* The leaf's own subject (CN=leaf.example) is no root subject. */
  {
    quic_x509 c;
    CHECK(
        quic_x509_parse(
            quic_castore_leaf_der, sizeof(quic_castore_leaf_der), &c) == 1);
    CHECK(quic_x509_subject(c.tbs, c.tbs_len, &dn, &dn_len) == 1);
  }
  CHECK(quic_castore_find_by_subject(&s, dn, dn_len, &root, &root_len) == 0);
}

static void test_add_rejects_malformed(void) {
  quic_castore s;
  const u8     junk[] = {0x00, 0x01, 0x02};
  quic_castore_init(&s);
  CHECK(quic_castore_add(&s, junk, sizeof(junk)) == 0);
}

static void test_add_full_store_fails(void) {
  quic_castore s;
  quic_castore_init(&s);
  for (usz i = 0; i < QUIC_CASTORE_MAX; i++)
    CHECK(
        quic_castore_add(
            &s, quic_castore_root_der, sizeof(quic_castore_root_der)) == 1);
  CHECK(
      quic_castore_add(
          &s, quic_castore_root_der, sizeof(quic_castore_root_der)) == 0);
}

void test_castore(void) {
  test_init_is_empty();
  test_add_then_find_by_leaf_issuer();
  test_find_unknown_subject_fails();
  test_add_rejects_malformed();
  test_add_full_store_fails();
}
