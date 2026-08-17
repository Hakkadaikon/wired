#include "tls/ext/salpn/idna.h"

#include "test.h"

/* An all-ASCII host (already an A-label, or never needed one) round-trips
 * verbatim. */
static void test_idna_ascii_passthrough(void) {
  const u8 host[] = "example.com";
  u8       out[32];
  usz      n = quic_salpn_idna_to_ascii(
      wired_span_of(host, sizeof(host) - 1), out, sizeof(out));
  CHECK(n == sizeof(host) - 1);
  for (usz i = 0; i < n; i++) CHECK(out[i] == host[i]);
}

/* An already-encoded A-label ("xn--...") is itself pure ASCII and passes
 * through unchanged -- RFC 6125 6.4.1 comparison needs no further decoding
 * of it. */
static void test_idna_alabel_passthrough(void) {
  const u8 host[] = "xn--caf-dma.example";
  u8       out[32];
  usz      n = quic_salpn_idna_to_ascii(
      wired_span_of(host, sizeof(host) - 1), out, sizeof(out));
  CHECK(n == sizeof(host) - 1);
  for (usz i = 0; i < n; i++) CHECK(out[i] == host[i]);
}

/* A raw U-label (actual non-ASCII codepoints, UTF-8 "café.example") is
 * rejected: Punycode U-label -> A-label conversion (RFC 3492) is not
 * implemented, and this returns 0 rather than emitting a wrong encoding. */
static void test_idna_non_ascii_rejected(void) {
  const u8 host[] = {'c', 'a', 'f', 0xc3, 0xa9, '.', 'e', 'x'};
  u8       out[32];
  CHECK(
      quic_salpn_idna_to_ascii(
          wired_span_of(host, sizeof(host)), out, sizeof(out)) == 0);
}

/* Output that does not fit the caller's buffer is rejected. */
static void test_idna_no_room(void) {
  const u8 host[] = "example.com";
  u8       out[4];
  CHECK(
      quic_salpn_idna_to_ascii(
          wired_span_of(host, sizeof(host) - 1), out, sizeof(out)) == 0);
}

void test_idna(void) {
  test_idna_ascii_passthrough();
  test_idna_alabel_passthrough();
  test_idna_non_ascii_rejected();
  test_idna_no_room();
}
