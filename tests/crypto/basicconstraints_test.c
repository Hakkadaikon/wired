#include "crypto/pki/encoding/x509/basicconstraints.h"

#include "castore_golden.h"
#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* cert1 carries basicConstraints with cA TRUE. */
static void test_ca_true(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_chain_golden1, sizeof(quic_chain_golden1)), &c) ==
      1);
  CHECK(quic_x509_is_ca(c.tbs) == 1);
}

/* cert2 has basicConstraints present but cA absent (DER-default FALSE). */
static void test_ca_false(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_chain_golden2, sizeof(quic_chain_golden2)), &c) ==
      1);
  CHECK(quic_x509_is_ca(c.tbs) == 0);
}

/* No extensions at all: not a CA. */
static void test_no_extensions(void) {
  const u8 tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  CHECK(quic_x509_is_ca(quic_span_of(tbs, sizeof(tbs))) == 0);
}

/* Offset of the BasicConstraints value {cA TRUE, pathLen 0} inside mid3's
 * DER: 30 06 01 01 ff 02 01 00. 0 if not found. */
static usz bc_pathlen_off(const u8 *der, usz len) {
  static const u8 pat[8] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00};
  for (usz i = 0; i + sizeof(pat) <= len; i++) {
    usz j = 0;
    while (j < sizeof(pat) && der[i + j] == pat[j]) j++;
    if (j == sizeof(pat)) return i;
  }
  return 0;
}

/* Copy mid3's DER, overwrite the byte at `rel` inside its BasicConstraints
 * TLV, and parse the copy. The caller owns `der` so the views stay alive. */
static void mid3_patched(usz rel, u8 v, u8 *der, quic_x509 *c) {
  usz off;
  for (usz i = 0; i < sizeof(quic_castore_mid3_der); i++)
    der[i] = quic_castore_mid3_der[i];
  off = bc_pathlen_off(der, sizeof(quic_castore_mid3_der));
  CHECK(off != 0);
  der[off + rel] = v;
  CHECK(
      quic_x509_parse(quic_span_of(der, sizeof(quic_castore_mid3_der)), c) ==
      1);
}

/* RFC 5280 6.1.4 (m): mid3 asserts pathlen:0, so depth 0 is admitted and
 * depth 1 is not (boundary pair). */
static void test_pathlen_allows_boundary(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_castore_mid3_der, sizeof(quic_castore_mid3_der)),
          &c) == 1);
  CHECK(quic_x509_pathlen_allows(c.tbs, 0) == 1);
  CHECK(quic_x509_pathlen_allows(c.tbs, 1) == 0);
}

/* A pathLenConstraint of 1 admits depth 1 and rejects depth 2. */
static void test_pathlen_allows_one(void) {
  u8        der[sizeof(quic_castore_mid3_der)];
  quic_x509 c;
  mid3_patched(7, 0x01, der, &c);
  CHECK(quic_x509_pathlen_allows(c.tbs, 1) == 1);
  CHECK(quic_x509_pathlen_allows(c.tbs, 2) == 0);
}

/* X.690 8.3 / RFC 5280: INTEGER (0..MAX) — a negative value rejects. */
static void test_pathlen_negative_rejected(void) {
  u8        der[sizeof(quic_castore_mid3_der)];
  quic_x509 c;
  mid3_patched(7, 0x80, der, &c);
  CHECK(quic_x509_pathlen_allows(c.tbs, 0) == 0);
}

/* A trailing element that is not an INTEGER rejects (fail closed). */
static void test_pathlen_not_integer_rejected(void) {
  u8        der[sizeof(quic_castore_mid3_der)];
  quic_x509 c;
  mid3_patched(5, 0x04, der, &c);
  CHECK(quic_x509_pathlen_allows(c.tbs, 0) == 0);
}

void test_basicconstraints(void) {
  test_ca_true();
  test_ca_false();
  test_no_extensions();
  test_pathlen_allows_boundary();
  test_pathlen_allows_one();
  test_pathlen_negative_rejected();
  test_pathlen_not_integer_rejected();
}
