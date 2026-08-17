#include "crypto/pki/encoding/x509/dirstring.h"

#include "test.h"

/* --- quic_x509_dirstring_ci_equal: raw DirectoryString content octets --- */

static const u8 dst_hello[]        = {'H', 'e', 'l', 'l', 'o'};
static const u8 dst_hello_lower[]  = {'h', 'e', 'l', 'l', 'o'};
static const u8 dst_world[]        = {'W', 'o', 'r', 'l', 'd'};
static const u8 dst_internal_ws[]  = {'A', ' ', ' ', 'B'};      /* "A  B" */
static const u8 dst_internal_one[] = {'A', ' ', 'B'};           /* "A B" */
static const u8 dst_padded[]       = {' ', ' ', 'A', 'B', ' '}; /* "  AB " */
static const u8 dst_bare[]         = {'A', 'B'};
static const u8 dst_non_ascii_a[]  = {0xc3, 0xa9}; /* U+00E9 UTF-8 */
static const u8 dst_non_ascii_b[]  = {0xc3, 0xa9}; /* identical bytes */
static const u8 dst_non_ascii_c[]  = {0xc3, 0xa8}; /* differs */

/* RFC 4518 2.3 (ASCII scope): differing case compares equal. */
static void test_dirstring_case_insensitive(void) {
  CHECK(
      quic_x509_dirstring_ci_equal(
          wired_span_of(dst_hello, sizeof(dst_hello)),
          wired_span_of(dst_hello_lower, sizeof(dst_hello_lower))) == 1);
}

/* Genuinely different content does not match. */
static void test_dirstring_different_rejects(void) {
  CHECK(
      quic_x509_dirstring_ci_equal(
          wired_span_of(dst_hello, sizeof(dst_hello)),
          wired_span_of(dst_world, sizeof(dst_world))) == 0);
}

/* RFC 4518 2.6.1: an internal run of 2+ spaces collapses to one space, so
 * "A  B" == "A B". */
static void test_dirstring_internal_space_collapses(void) {
  CHECK(
      quic_x509_dirstring_ci_equal(
          wired_span_of(dst_internal_ws, sizeof(dst_internal_ws)),
          wired_span_of(dst_internal_one, sizeof(dst_internal_one))) == 1);
}

/* RFC 4518 2.6.1: leading/trailing spaces are insignificant, so "  AB " ==
 * "AB". */
static void test_dirstring_leading_trailing_trimmed(void) {
  CHECK(
      quic_x509_dirstring_ci_equal(
          wired_span_of(dst_padded, sizeof(dst_padded)),
          wired_span_of(dst_bare, sizeof(dst_bare))) == 1);
}

/* Non-ASCII content this SDK does not case-fold falls back to byte-exact
 * comparison: identical bytes still match. */
static void test_dirstring_non_ascii_identical_matches(void) {
  CHECK(
      quic_x509_dirstring_ci_equal(
          wired_span_of(dst_non_ascii_a, sizeof(dst_non_ascii_a)),
          wired_span_of(dst_non_ascii_b, sizeof(dst_non_ascii_b))) == 1);
}

/* Non-ASCII content that actually differs is rejected (fails closed, no
 * folding attempted). */
static void test_dirstring_non_ascii_different_rejects(void) {
  CHECK(
      quic_x509_dirstring_ci_equal(
          wired_span_of(dst_non_ascii_a, sizeof(dst_non_ascii_a)),
          wired_span_of(dst_non_ascii_c, sizeof(dst_non_ascii_c))) == 0);
}

/* --- quic_x509_dn_equal_ci: full Name comparison --- */

/* Name { RDN { commonName = "Example CA" } }. */
static const u8 dst_n1[] = {
    0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
};

/* Same DN, lowercased commonName value. */
static const u8 dst_n2[] = {
    0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0a, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x63, 0x61,
};

/* Same DN, "Example  CA" (double internal space). */
static const u8 dst_n3[] = {
    0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x20, 0x43, 0x41,
};

/* Same DN, "  Example CA  " (leading/trailing spaces). */
static const u8 dst_n4[] = {
    0x30, 0x19, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x0e, 0x20, 0x20, 0x45, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41, 0x20, 0x20,
};

/* Different commonName value entirely: "Different CA". */
static const u8 dst_n5[] = {
    0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x0c, 0x44, 0x69, 0x66, 0x66, 0x65,
    0x72, 0x65, 0x6e, 0x74, 0x20, 0x43, 0x41,
};

/* Same value "Example CA" but attribute type is organizationalUnitName, not
 * commonName. */
static const u8 dst_n6[] = {
    0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c,
    0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
};

/* Name { RDN { commonName = "Example CA", OU = "Eng" } } -- a second ATV in
 * the same (multi-valued) RDN. */
static const u8 dst_n7[] = {
    0x30, 0x21, 0x31, 0x1f, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41, 0x30,
    0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x45, 0x6e, 0x67,
};

/* Name { RDN { commonName = "Example CA" }, RDN { OU = "Eng" } } -- the same
 * attributes as dst_n7 but split across two RDNs instead of one. */
static const u8 dst_n8[] = {
    0x30, 0x23, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x20, 0x43, 0x41, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55,
    0x04, 0x0b, 0x0c, 0x03, 0x45, 0x6e, 0x67,
};

/* RFC 5280 7.1: DN comparison is caseIgnoreMatch -- differing case in a
 * commonName value still matches. */
static void test_dn_ci_case_insensitive(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n2, sizeof(dst_n2))) == 1);
}

/* Internal whitespace run collapses within a DN's attribute value too. */
static void test_dn_ci_internal_space_collapses(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n3, sizeof(dst_n3))) == 1);
}

/* Leading/trailing whitespace trimmed within a DN's attribute value too. */
static void test_dn_ci_leading_trailing_trimmed(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n4, sizeof(dst_n4))) == 1);
}

/* A genuinely different commonName value does not match. */
static void test_dn_ci_different_value_rejects(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n5, sizeof(dst_n5))) == 0);
}

/* Same string value under a different attribute type OID does not match. */
static void test_dn_ci_different_type_rejects(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n6, sizeof(dst_n6))) == 0);
}

/* A DN with an extra attribute in its (multi-valued) RDN does not match a
 * DN missing that attribute. */
static void test_dn_ci_extra_attribute_rejects(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n7, sizeof(dst_n7))) == 0);
}

/* The same two attributes encoded as one multi-valued RDN vs. two separate
 * RDNs do not match (this SDK does not fold RDN grouping differences). */
static void test_dn_ci_rdn_grouping_rejects(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n7, sizeof(dst_n7)),
          wired_span_of(dst_n8, sizeof(dst_n8))) == 0);
}

/* A DN compares equal to itself. */
static void test_dn_ci_reflexive(void) {
  CHECK(
      quic_x509_dn_equal_ci(
          wired_span_of(dst_n1, sizeof(dst_n1)),
          wired_span_of(dst_n1, sizeof(dst_n1))) == 1);
}

void test_dirstring(void) {
  test_dirstring_case_insensitive();
  test_dirstring_different_rejects();
  test_dirstring_internal_space_collapses();
  test_dirstring_leading_trailing_trimmed();
  test_dirstring_non_ascii_identical_matches();
  test_dirstring_non_ascii_different_rejects();
  test_dn_ci_case_insensitive();
  test_dn_ci_internal_space_collapses();
  test_dn_ci_leading_trailing_trimmed();
  test_dn_ci_different_value_rejects();
  test_dn_ci_different_type_rejects();
  test_dn_ci_extra_attribute_rejects();
  test_dn_ci_rdn_grouping_rejects();
  test_dn_ci_reflexive();
}
