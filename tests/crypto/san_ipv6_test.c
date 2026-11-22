#include "crypto/pki/encoding/x509/san_impl.h"
#include "test.h"

/* Parse a string literal as an IPv6 reference identity. */
static int s6_parse(const char* s, u8 out[SAN_IPV6_LEN]) {
  return san_ipv6_parse(wired_span_of((const u8*)s, wired_cstr_len(s)), out);
}

/* s parses and yields exactly want. */
static int s6_is(const char* s, const u8 want[SAN_IPV6_LEN]) {
  u8 got[SAN_IPV6_LEN];
  return s6_parse(s, got) && ct_diffn(got, want, SAN_IPV6_LEN) == 0;
}

static int s6_bad(const char* s) {
  u8 got[SAN_IPV6_LEN];
  return s6_parse(s, got) == 0;
}

/* RFC 4291 2.2 form 1 (x:x:x:x:x:x:x:x) and form 2 ("::" once, leading,
 * middle or trailing), hex digits of either case. */
static void test_san_ipv6_parse_forms(void) {
  static const u8 doc1[SAN_IPV6_LEN]  = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                         0,    0,    0,    0,    0, 0, 0, 1};
  static const u8 lo[SAN_IPV6_LEN]    = {0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 1};
  static const u8 zero[SAN_IPV6_LEN]  = {0};
  static const u8 pre[SAN_IPV6_LEN]   = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                         0,    0,    0,    0,    0, 0, 0, 0};
  static const u8 seven[SAN_IPV6_LEN] = {0, 1, 0, 2, 0, 3, 0, 4,
                                         0, 5, 0, 6, 0, 7, 0, 0};
  static const u8 abcd[SAN_IPV6_LEN]  = {
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd};
  CHECK(s6_is("2001:db8:0:0:0:0:0:1", doc1));
  CHECK(s6_is("2001:0db8:0000:0000:0000:0000:0000:0001", doc1));
  CHECK(s6_is("2001:db8::1", doc1));
  CHECK(s6_is("2001:db8:0::0:1", doc1));
  CHECK(s6_is("::1", lo));
  CHECK(s6_is("::", zero));
  CHECK(s6_is("2001:db8::", pre));
  CHECK(s6_is("1:2:3:4:5:6:7::", seven));
  CHECK(s6_is("2001:DB8::ABCD", abcd));
  CHECK(s6_is("2001:Db8::aBcD", abcd));
}

/* The "::" boundary with an IPv4 tail: 5 groups + 4 octets leave room for
 * one zero group (accepted); 6 groups + 4 octets leave none (rejected). */
static void test_san_ipv6_parse_dcolon_boundary(void) {
  static const u8 five[SAN_IPV6_LEN] = {0, 1, 0, 2, 0, 3, 0, 4,
                                        0, 5, 0, 0, 1, 2, 3, 4};
  CHECK(s6_is("1:2:3:4:5::1.2.3.4", five));
  CHECK(s6_bad("1:2:3:4:5:6::1.2.3.4"));
}

/* RFC 3986 3.2.2 IPv4address: no separator after the fourth octet, on its
 * own or as an IPv6 tail. */
static void test_san_ipv4_trailing_dot(void) {
  u8 v4[SAN_IPV4_LEN];
  CHECK(san_ipv4_parse(wired_span_of((const u8*)"1.2.3.4.", 8), v4) == 0);
  CHECK(san_ipv4_parse(wired_span_of((const u8*)"1.2.3.4", 7), v4) == 1);
  CHECK(s6_bad("::1.2.3.4."));
}

/* RFC 4291 2.2 form 3: a dotted-decimal IPv4 tail as the low 32 bits. */
static void test_san_ipv6_parse_ipv4_tail(void) {
  static const u8 mapped[SAN_IPV6_LEN] = {0, 0, 0,    0,    0,    0, 0, 0,
                                          0, 0, 0xff, 0xff, 0xc0, 0, 2, 1};
  CHECK(s6_is("::ffff:192.0.2.1", mapped));
  CHECK(s6_is("0:0:0:0:0:ffff:192.0.2.1", mapped));
  CHECK(s6_is("::FFFF:192.0.2.1", mapped));
}

/* Malformed text forms, and RFC 6874 zone IDs (rejected: a zone is local to
 * the host that wrote it and no certificate can name it). */
static void test_san_ipv6_parse_malformed(void) {
  static const char* bad[] = {
      "",
      ":",
      ":::",
      "1::2::3",
      "::1::",
      "1:2:3:4:5:6:7:8:9",
      "1:2:3:4:5:6:7::8",
      "1:2:3:4:5:6:7",
      "12345::",
      "::12345",
      "1:2:3:4:5:6:7:",
      ":1:2:3:4:5:6:7:8",
      "1::2:",
      "1:::2",
      "::1g",
      "::1 ",
      "::g",
      "::1.2.3",
      "::1.2.3.256",
      "::01.2.3.4",
      "::1.2.3.4:5",
      "::1.2.3.4.",
      "1.2.3.4::",
      "1:2:3:4:5:6:7:1.2.3.4",
      "1.2.3.4",
      "[::1]",
      "fe80::1%eth0",
      "fe80::1%25eth0",
  };
  for (usz i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    CHECK(s6_bad(bad[i]));
  }
}

/* tbs stand-in shaped like san_test.c's: 6 NULL fillers, then [3]
 * { SEQUENCE { Extension { subjectAltName, OCTET STRING { GeneralNames } } } }
 * holding one iPAddress [7] of 16 octets: 2001:db8::1. */
static const u8 san6_tbs[] = {
    0x30, 0x2d, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x1f, 0x30, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x1d,
    0x11, 0x04, 0x14, 0x30, 0x12, 0x87, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

/* Same shape, one iPAddress of 4 octets: 127.0.0.1. */
static const u8 san6_v4_tbs[] = {
    0x30, 0x21, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
    0x11, 0x04, 0x08, 0x30, 0x06, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01,
};

/* Same shape, one dNSName [2] "::1". */
static const u8 san6_dns_tbs[] = {
    0x30, 0x20, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x12, 0x30, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x11, 0x04, 0x07, 0x30, 0x05, 0x82, 0x03, 0x3a, 0x3a, 0x31,
};

/* SAN-less tbs stand-ins (4 NULL fillers, then a subject with one CN):
 * CN "2001:db8::1" and CN "*.2.3.4". */
static const u8 san6_cn_v6_tbs[] = {
    0x30, 0x20, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x30, 0x16,
    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x32,
    0x30, 0x30, 0x31, 0x3a, 0x64, 0x62, 0x38, 0x3a, 0x3a, 0x31,
};

static const u8 san6_cn_wild_tbs[] = {
    0x30, 0x1c, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x07, 0x2a, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34,
};

static int s6_match(const u8* tbs, usz n, const char* host) {
  return x509_san_matches(
      wired_span_of(tbs, n),
      wired_span_of((const u8*)host, wired_cstr_len(host)));
}

/* RFC 9525 6.3 / RFC 5280 4.2.1.6: an IPv6 reference identity matches a
 * 16-octet iPAddress entry by octet equality, whatever its text form. */
static void test_san_ipv6_match(void) {
  CHECK(s6_match(san6_tbs, sizeof san6_tbs, "2001:db8::1") == 1);
  CHECK(s6_match(san6_tbs, sizeof san6_tbs, "2001:DB8:0:0:0:0:0:1") == 1);
  CHECK(s6_match(san6_tbs, sizeof san6_tbs, "2001:db8::2") == 0);
  CHECK(s6_match(san6_tbs, sizeof san6_tbs, "::1") == 0);
  CHECK(s6_match(san6_tbs, sizeof san6_tbs, "2001:db8::1%25eth0") == 0);
}

/* Octet equality across lengths: a 4-octet entry never matches an IPv6
 * identity, the v4-mapped ::ffff:127.0.0.1 included; the IPv4 literal
 * still matches it. */
static void test_san_ipv6_vs_ipv4_entry(void) {
  CHECK(s6_match(san6_v4_tbs, sizeof san6_v4_tbs, "::ffff:127.0.0.1") == 0);
  CHECK(s6_match(san6_v4_tbs, sizeof san6_v4_tbs, "::127.0.0.1") == 0);
  CHECK(s6_match(san6_v4_tbs, sizeof san6_v4_tbs, "127.0.0.1") == 1);
}

/* RFC 9525 6.3: an IP reference identity is never compared with a dNSName,
 * even one spelling the same text. */
static void test_san_ipv6_no_dnsname(void) {
  CHECK(s6_match(san6_dns_tbs, sizeof san6_dns_tbs, "::1") == 0);
}

/* RFC 9525 6.3 / RFC 2818 3.1: an IP reference identity needs an
 * iPAddress SAN; the CN-ID fallback (RFC 6125 6.4.4) is for DNS names only,
 * so neither a literal CN nor a wildcard CN covering its text matches. */
static void test_san_ip_no_cn_id(void) {
  CHECK(s6_match(san6_cn_v6_tbs, sizeof san6_cn_v6_tbs, "2001:db8::1") == 0);
  CHECK(s6_match(san6_cn_wild_tbs, sizeof san6_cn_wild_tbs, "1.2.3.4") == 0);
  CHECK(
      s6_match(san6_cn_wild_tbs, sizeof san6_cn_wild_tbs, "::ffff:1.2.3.4") ==
      0);
  CHECK(s6_match(san6_cn_wild_tbs, sizeof san6_cn_wild_tbs, "a.2.3.4") == 1);
}

void test_san_ipv6(void) {
  test_san_ipv6_parse_dcolon_boundary();
  test_san_ipv4_trailing_dot();
  test_san_ip_no_cn_id();
  test_san_ipv6_parse_forms();
  test_san_ipv6_parse_ipv4_tail();
  test_san_ipv6_parse_malformed();
  test_san_ipv6_match();
  test_san_ipv6_vs_ipv4_entry();
  test_san_ipv6_no_dnsname();
}
