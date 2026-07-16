#include "app/http3/core/sfield/sfield.h"

#include "test.h"

/* @file
 * RFC 8941 Structured Fields subset tests: sf-list of sf-strings parse
 * (SS3.1 / SS3.3.3) and sf-string serialize (SS4.1.6).
 */

static int sfield_bytes_eq(const u8* p, const char* s, usz n) {
  for (usz i = 0; i < n; i++)
    if (p[i] != (u8)s[i]) return 0;
  return 1;
}

static int sfield_obuf_is(const quic_obuf* out, const char* s, usz n) {
  return out->len == n && sfield_bytes_eq(out->p, s, n);
}

static quic_span sfield_span(const char* s, usz n) {
  return quic_span_of((const u8*)s, n);
}

static void test_sfield_single_item(void) {
  quic_sfield_iter it;
  u8               buf[16];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  quic_sfield_iter_init(&it, sfield_span("\"foo\"", 5));
  CHECK(quic_sfield_next_string(&it, &out) == 1);
  CHECK(sfield_obuf_is(&out, "foo", 3));
  CHECK(quic_sfield_next_string(&it, &out) == 0);
}

static void test_sfield_multiple_items_in_order(void) {
  quic_sfield_iter it;
  u8               b1[16], b2[16];
  quic_obuf        o1 = quic_obuf_of(b1, sizeof b1);
  quic_obuf        o2 = quic_obuf_of(b2, sizeof b2);

  quic_sfield_iter_init(&it, sfield_span("\"foo\", \"bar\"", 12));
  CHECK(quic_sfield_next_string(&it, &o1) == 1);
  CHECK(sfield_obuf_is(&o1, "foo", 3));
  CHECK(quic_sfield_next_string(&it, &o2) == 1);
  CHECK(sfield_obuf_is(&o2, "bar", 3));
  CHECK(quic_sfield_next_string(&it, &o2) == 0);
}

static void test_sfield_comma_and_space_inside_quotes(void) {
  quic_sfield_iter it;
  u8               buf[16];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  quic_sfield_iter_init(&it, sfield_span("\"a, b\"", 6));
  CHECK(quic_sfield_next_string(&it, &out) == 1);
  CHECK(sfield_obuf_is(&out, "a, b", 4));
  CHECK(quic_sfield_next_string(&it, &out) == 0);
}

static void test_sfield_escaped_quote_and_backslash(void) {
  quic_sfield_iter it;
  u8               b1[16], b2[16];
  quic_obuf        o1 = quic_obuf_of(b1, sizeof b1);
  quic_obuf        o2 = quic_obuf_of(b2, sizeof b2);

  /* raw input: "a\"b", "a\\b" */
  quic_sfield_iter_init(&it, sfield_span("\"a\\\"b\", \"a\\\\b\"", 15));
  CHECK(quic_sfield_next_string(&it, &o1) == 1);
  CHECK(sfield_obuf_is(&o1, "a\"b", 3));
  CHECK(quic_sfield_next_string(&it, &o2) == 1);
  CHECK(sfield_obuf_is(&o2, "a\\b", 3));
}

static void test_sfield_empty_and_ws_only_input_yields_no_items(void) {
  quic_sfield_iter it;
  u8               buf[8];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  quic_sfield_iter_init(&it, quic_span_of(0, 0));
  CHECK(quic_sfield_next_string(&it, &out) == 0);

  quic_sfield_iter_init(&it, sfield_span(" \t ", 3));
  CHECK(quic_sfield_next_string(&it, &out) == 0);
}

static void test_sfield_bare_token_is_error(void) {
  quic_sfield_iter it;
  u8               buf[8];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  quic_sfield_iter_init(&it, sfield_span("foo", 3));
  CHECK(quic_sfield_next_string(&it, &out) == -1);
}

static void test_sfield_bare_integer_is_error(void) {
  quic_sfield_iter it;
  u8               buf[8];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  quic_sfield_iter_init(&it, sfield_span("123", 3));
  CHECK(quic_sfield_next_string(&it, &out) == -1);
}

static void test_sfield_bad_escape_is_error(void) {
  quic_sfield_iter it;
  u8               buf[8];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  /* raw input: "a\x" -- only \" and \\ are valid (RFC 8941 SS3.3.3) */
  quic_sfield_iter_init(&it, sfield_span("\"a\\x\"", 5));
  CHECK(quic_sfield_next_string(&it, &out) == -1);
}

static void test_sfield_missing_close_quote_is_error(void) {
  quic_sfield_iter it;
  u8               buf[8];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  quic_sfield_iter_init(&it, sfield_span("\"foo", 4));
  CHECK(quic_sfield_next_string(&it, &out) == -1);
}

static void test_sfield_parameters_are_skipped(void) {
  quic_sfield_iter it;
  u8               b1[16], b2[16];
  quic_obuf        o1 = quic_obuf_of(b1, sizeof b1);
  quic_obuf        o2 = quic_obuf_of(b2, sizeof b2);

  quic_sfield_iter_init(&it, sfield_span("\"foo\";q=1, \"bar\"", 16));
  CHECK(quic_sfield_next_string(&it, &o1) == 1);
  CHECK(sfield_obuf_is(&o1, "foo", 3));
  CHECK(quic_sfield_next_string(&it, &o2) == 1);
  CHECK(sfield_obuf_is(&o2, "bar", 3));
  CHECK(quic_sfield_next_string(&it, &o2) == 0);
}

static void test_sfield_encode_parse_roundtrip(void) {
  u8               enc[16];
  usz              len;
  quic_sfield_iter it;
  u8               buf[16];
  quic_obuf        out = quic_obuf_of(buf, sizeof buf);

  len = quic_sfield_string_encode(enc, sizeof enc, sfield_span("foo", 3));
  CHECK(len == 5);
  CHECK(sfield_bytes_eq(enc, "\"foo\"", 5));

  quic_sfield_iter_init(&it, quic_span_of(enc, len));
  CHECK(quic_sfield_next_string(&it, &out) == 1);
  CHECK(sfield_obuf_is(&out, "foo", 3));
}

static void test_sfield_encode_escapes_quote_and_backslash(void) {
  u8  enc[16];
  usz len;

  len = quic_sfield_string_encode(enc, sizeof enc, sfield_span("a\"b", 3));
  CHECK(len == 6);
  CHECK(sfield_bytes_eq(enc, "\"a\\\"b\"", 6));

  len = quic_sfield_string_encode(enc, sizeof enc, sfield_span("a\\b", 3));
  CHECK(len == 6);
  CHECK(sfield_bytes_eq(enc, "\"a\\\\b\"", 6));
}

static void test_sfield_encode_too_small_or_control_returns_zero(void) {
  u8 enc[16];

  /* "foo" needs 5 bytes incl. quotes; cap 4 must fail */
  CHECK(quic_sfield_string_encode(enc, 4, sfield_span("foo", 3)) == 0);
  /* 0x01 and 0x7f are outside %x20-7E (RFC 8941 SS3.3.3) */
  CHECK(
      quic_sfield_string_encode(enc, sizeof enc, sfield_span("a\x01", 2)) == 0);
  CHECK(
      quic_sfield_string_encode(enc, sizeof enc, sfield_span("a\x7f", 2)) == 0);
}

void test_sfield(void) {
  test_sfield_single_item();
  test_sfield_multiple_items_in_order();
  test_sfield_comma_and_space_inside_quotes();
  test_sfield_escaped_quote_and_backslash();
  test_sfield_empty_and_ws_only_input_yields_no_items();
  test_sfield_bare_token_is_error();
  test_sfield_bare_integer_is_error();
  test_sfield_bad_escape_is_error();
  test_sfield_missing_close_quote_is_error();
  test_sfield_parameters_are_skipped();
  test_sfield_encode_parse_roundtrip();
  test_sfield_encode_escapes_quote_and_backslash();
  test_sfield_encode_too_small_or_control_returns_zero();
}
