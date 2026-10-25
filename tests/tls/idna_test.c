#include "tls/ext/salpn/idna.h"

#include "common/bytes/util/bytes.h"
#include "test.h"

/* An all-ASCII host (already an A-label, or never needed one) round-trips
 * verbatim. */
static void test_idna_ascii_passthrough(void) {
  const u8 host[] = "example.com";
  u8       out[32];
  usz      n = salpn_idna_to_ascii(
      wired_span_of(host, sizeof(host) - 1), out, sizeof(out));
  CHECK(n == sizeof(host) - 1);
  for (usz i = 0; i < n; i++) {
    CHECK(out[i] == host[i]);
  }
}

/* An already-encoded A-label ("xn--...") is itself pure ASCII and passes
 * through unchanged -- RFC 6125 6.4.1 comparison needs no further decoding
 * of it. */
static void test_idna_alabel_passthrough(void) {
  const u8 host[] = "xn--caf-dma.example";
  u8       out[32];
  usz      n = salpn_idna_to_ascii(
      wired_span_of(host, sizeof(host) - 1), out, sizeof(out));
  CHECK(n == sizeof(host) - 1);
  for (usz i = 0; i < n; i++) {
    CHECK(out[i] == host[i]);
  }
}

/* idna_to_ascii(in) equals want (NUL-terminated), or fails when want is 0. */
static void idna_check(const char* in, const char* want) {
  u8  out[128];
  usz n = salpn_idna_to_ascii(
      wired_span_of((const u8*)in, wired_cstr_len(in)), out, sizeof(out));
  if (!want) {
    CHECK(n == 0);
    return;
  }
  CHECK(n == wired_cstr_len(want));
  for (usz i = 0; i < n && i < wired_cstr_len(want); i++) {
    CHECK(out[i] == (u8)want[i]);
  }
}

/* RFC 6125 6.4.2: U-labels become A-labels before matching. Vectors: RFC
 * 3492 7.1 (L) and (M), and "caf\u00e9" / "b\u00fccher", each re-derived
 * with Python's independent punycode codec. Only the non-ASCII labels
 * change. */
static void test_idna_ulabel_to_alabel(void) {
  idna_check("caf\xc3\xa9.example", "xn--caf-dma.example");
  idna_check(
      "www.b\xc3\xbc"
      "cher.de",
      "www.xn--bcher-kva.de");
  idna_check("\xc3\xbc", "xn--tda");
  idna_check(
      "3\xe5\xb9\xb4"
      "B\xe7\xb5\x84\xe9\x87\x91\xe5\x85\xab"
      "\xe5\x85\x88\xe7\x94\x9f",
      "xn--3B-ww4c5e180e575a65lsy2b");
  idna_check(
      "\xe5\xae\x89\xe5\xae\xa4\xe5\xa5\x88\xe7\xbe\x8e\xe6\x81\xb5"
      "-with-SUPER-MONKEYS",
      "xn---with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n");
}

/* Malformed input fails closed: an empty name or label, a stray
 * continuation byte, an overlong form, a surrogate, a truncated sequence,
 * and a U-label whose A-label passes 63 octets. */
static void test_idna_rejects(void) {
  idna_check("", 0);
  idna_check("a..b", 0);
  idna_check("\x80x", 0);
  idna_check("\xc0\xaf", 0);
  idna_check("\xed\xa0\x80", 0);
  idna_check("caf\xc3", 0);
  idna_check(
      "\xe4\xb8\x80\xe6\xb3\xaf\xe8\xaf\x9e\xe5\xb2\xad\xe7\xae\x9c"
      "\xe9\xaa\x8b\xe6\xad\x9a\xe8\xa9\x89\xe5\xac\x98\xe7\xa8\x87"
      "\xe9\xa3\xb6\xe6\xa7\x85\xe8\xa2\xb4\xe5\xa6\x83\xe7\xa1\xb2"
      "\xe9\x9d\xa1\xe6\xa0\xb0\xe8\x9c\x9f\xe5\x9f\xae\xe7\x9b\x9d",
      0); /* 20 code points: a 68-octet A-label */
}

/* Output that does not fit the caller's buffer is rejected. */
static void test_idna_no_room(void) {
  const u8 host[] = "example.com";
  u8       out[4];
  CHECK(
      salpn_idna_to_ascii(
          wired_span_of(host, sizeof(host) - 1), out, sizeof(out)) == 0);
}

void test_idna(void) {
  test_idna_ascii_passthrough();
  test_idna_alabel_passthrough();
  test_idna_ulabel_to_alabel();
  test_idna_rejects();
  test_idna_no_room();
}
