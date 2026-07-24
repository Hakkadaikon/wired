#include "app/webtransport/wtwire/wtwire.h"

#include "test.h"

/* @file
 * WebTransport wire-format helpers: stream signal prefixes, RFC 9297
 * quarter-stream-ID datagram prefixes, and the interop-runner line protocol
 * (GET / PUSH) as used by the webtransport-go reference implementation.
 */

/* TEST 1: uni signal prefix is varint(0x54) then varint(session_id).
 * 0x54 > 0x3F, so its varint form is the 2-byte {0x40, 0x54} (RFC 9000 16;
 * see also QUIC_H3_STREAM_WEBTRANSPORT in app/http3/core/h3/frame.h). */
static void test_wtwire_signal_put_uni(void) {
  u8 buf[16];

  CHECK(quic_wtwire_signal_put(buf, sizeof buf, 0, 0) == 3);
  CHECK(buf[0] == 0x40);
  CHECK(buf[1] == 0x54);
  CHECK(buf[2] == 0x00);

  CHECK(quic_wtwire_signal_put(buf, sizeof buf, 0, 4) == 3);
  CHECK(buf[2] == 0x04);

  /* session_id 100 needs a 2-byte varint: 0x40 0x64. */
  CHECK(quic_wtwire_signal_put(buf, sizeof buf, 0, 100) == 4);
  CHECK(buf[2] == 0x40);
  CHECK(buf[3] == 0x64);
}

/* TEST 2: bidi signal prefix is varint(0x41) = {0x40, 0x41}. */
static void test_wtwire_signal_put_bidi(void) {
  u8 buf[16];

  CHECK(quic_wtwire_signal_put(buf, sizeof buf, 1, 4) == 3);
  CHECK(buf[0] == 0x40);
  CHECK(buf[1] == 0x41);
  CHECK(buf[2] == 0x04);
}

/* TEST 2b: signal_put boundary capacity: exact fits, one short fails. */
static void test_wtwire_signal_put_capacity(void) {
  u8 buf[4];

  CHECK(quic_wtwire_signal_put(buf, 3, 0, 4) == 3);
  CHECK(quic_wtwire_signal_put(buf, 2, 0, 4) == 0);
  CHECK(quic_wtwire_signal_put(buf, 0, 0, 4) == 0);
}

/* TEST 3: qsid prefix is varint(session_id / 4). */
static void test_wtwire_qsid_put(void) {
  u8 buf[8];

  CHECK(quic_wtwire_qsid_put(buf, sizeof buf, 4) == 1);
  CHECK(buf[0] == 0x01);

  CHECK(quic_wtwire_qsid_put(buf, sizeof buf, 0) == 1);
  CHECK(buf[0] == 0x00);

  /* 400 / 4 = 100 -> 2-byte varint 0x40 0x64. */
  CHECK(quic_wtwire_qsid_put(buf, sizeof buf, 400) == 2);
  CHECK(buf[0] == 0x40);
  CHECK(buf[1] == 0x64);

  CHECK(quic_wtwire_qsid_put(buf, 1, 400) == 0);
  CHECK(quic_wtwire_qsid_put(buf, 0, 0) == 0);
}

/* TEST 4: qsid put -> take round-trips session_id and consumed length. */
static void test_wtwire_qsid_roundtrip(void) {
  u8  buf[8];
  usz n;
  u64 sid = 0;

  n = quic_wtwire_qsid_put(buf, sizeof buf, 400);
  CHECK(n == 2);
  CHECK(quic_wtwire_qsid_take(quic_span_of(buf, n), &sid) == n);
  CHECK(sid == 400);

  n = quic_wtwire_qsid_put(buf, sizeof buf, 4);
  CHECK(quic_wtwire_qsid_take(quic_span_of(buf, n), &sid) == n);
  CHECK(sid == 4);
}

/* TEST 5: qsid_take rejects an empty span and a truncated varint. */
static void test_wtwire_qsid_take_malformed(void) {
  u8  two = 0x40; /* first byte of a 2-byte varint, second byte missing */
  u64 sid;

  CHECK(quic_wtwire_qsid_take(quic_span_of(0, 0), &sid) == 0);
  CHECK(quic_wtwire_qsid_take(quic_span_of(&two, 1), &sid) == 0);
}

/* TEST 5b: qsid_take rejects a QSID above 2^60-1 (RFC 9297 2.1); accepts the
 * boundary value itself. */
static void test_wtwire_qsid_take_range(void) {
  u8  buf[16];
  usz n;
  u64 sid;

  /* 2^60-1: the largest legal QSID. */
  n = quic_wtwire_qsid_put(buf, sizeof buf, (((u64)1 << 60) - 1) * 4);
  CHECK(n != 0);
  CHECK(quic_wtwire_qsid_take(quic_span_of(buf, n), &sid) == n);
  CHECK(sid == (((u64)1 << 60) - 1) * 4);

  /* 2^60: one past the legal range -> rejected. */
  n = quic_wtwire_qsid_put(buf, sizeof buf, ((u64)1 << 60) * 4);
  CHECK(n != 0);
  CHECK(quic_wtwire_qsid_take(quic_span_of(buf, n), &sid) == 0);
}

static int span_is(quic_span s, const char* str, usz n) {
  if (s.n != n) return 0;
  for (usz i = 0; i < n; i++)
    if (s.p[i] != (u8)str[i]) return 0;
  return 1;
}

/* TEST 6: GET line parses; filename is trimmed of surrounding whitespace. */
static void test_wtwire_get_parse_ok(void) {
  u8        a[] = "GET foo.txt";
  u8        b[] = "GET foo.txt\n";
  u8        c[] = "GET  foo ";
  quic_span file;

  CHECK(quic_wtwire_get_parse(quic_span_of(a, sizeof a - 1), &file));
  CHECK(span_is(file, "foo.txt", 7));
  CHECK(quic_wtwire_get_parse(quic_span_of(b, sizeof b - 1), &file));
  CHECK(span_is(file, "foo.txt", 7));
  CHECK(quic_wtwire_get_parse(quic_span_of(c, sizeof c - 1), &file));
  CHECK(span_is(file, "foo", 3));
}

/* TEST 7: GET line rejected on empty name, wrong verb, or short input. */
static void test_wtwire_get_parse_reject(void) {
  u8        a[] = "GET ";
  u8        b[] = "PUT x";
  u8        c[] = "GE";
  quic_span file;

  CHECK(!quic_wtwire_get_parse(quic_span_of(a, sizeof a - 1), &file));
  CHECK(!quic_wtwire_get_parse(quic_span_of(b, sizeof b - 1), &file));
  CHECK(!quic_wtwire_get_parse(quic_span_of(c, sizeof c - 1), &file));
}

/* TEST 8: get_put round-trips through get_parse; boundary capacity. */
static void test_wtwire_get_put_roundtrip(void) {
  u8        name[] = "foo.txt";
  u8        buf[16];
  usz       n;
  quic_span file;

  n = quic_wtwire_get_put(buf, sizeof buf, quic_span_of(name, 7));
  CHECK(n == 11);
  CHECK(quic_wtwire_get_parse(quic_span_of(buf, n), &file));
  CHECK(span_is(file, "foo.txt", 7));

  CHECK(quic_wtwire_get_put(buf, 11, quic_span_of(name, 7)) == 11);
  CHECK(quic_wtwire_get_put(buf, 10, quic_span_of(name, 7)) == 0);
}

/* TEST 9: PUSH header parses into name and content; empty content ok. */
static void test_wtwire_push_parse_ok(void) {
  u8        a[] = "PUSH a.txt\nHELLO";
  u8        b[] = "PUSH a\n";
  quic_span name, content;

  CHECK(quic_wtwire_push_parse(quic_span_of(a, sizeof a - 1), &name, &content));
  CHECK(span_is(name, "a.txt", 5));
  CHECK(span_is(content, "HELLO", 5));

  CHECK(quic_wtwire_push_parse(quic_span_of(b, sizeof b - 1), &name, &content));
  CHECK(span_is(name, "a", 1));
  CHECK(content.n == 0);
}

/* TEST 10: PUSH rejected without newline, empty name, or wrong prefix. */
static void test_wtwire_push_parse_reject(void) {
  u8        a[] = "PUSH a.txt";
  u8        b[] = "PUSH \nX";
  u8        c[] = "PULL a\nX";
  quic_span name, content;

  CHECK(
      !quic_wtwire_push_parse(quic_span_of(a, sizeof a - 1), &name, &content));
  CHECK(
      !quic_wtwire_push_parse(quic_span_of(b, sizeof b - 1), &name, &content));
  CHECK(
      !quic_wtwire_push_parse(quic_span_of(c, sizeof c - 1), &name, &content));
}

/* TEST 11: push_head_put round-trips through push_parse; boundary capacity. */
static void test_wtwire_push_head_put_roundtrip(void) {
  u8        base[] = "a.txt";
  u8        buf[16];
  usz       n;
  quic_span name, content;

  n = quic_wtwire_push_head_put(buf, sizeof buf, quic_span_of(base, 5));
  CHECK(n == 11);
  CHECK(buf[n - 1] == '\n');
  CHECK(quic_wtwire_push_parse(quic_span_of(buf, n), &name, &content));
  CHECK(span_is(name, "a.txt", 5));
  CHECK(content.n == 0);

  CHECK(quic_wtwire_push_head_put(buf, 11, quic_span_of(base, 5)) == 11);
  CHECK(quic_wtwire_push_head_put(buf, 10, quic_span_of(base, 5)) == 0);
}

/* TEST 12: basename returns the view after the last '/'. */
static void test_wtwire_basename(void) {
  u8 a[] = "dir/f.txt";
  u8 b[] = "f.txt";
  u8 c[] = "a/b/c";
  u8 d[] = "a/";

  CHECK(span_is(quic_wtwire_basename(quic_span_of(a, 9)), "f.txt", 5));
  CHECK(span_is(quic_wtwire_basename(quic_span_of(b, 5)), "f.txt", 5));
  CHECK(span_is(quic_wtwire_basename(quic_span_of(c, 5)), "c", 1));
  CHECK(quic_wtwire_basename(quic_span_of(d, 2)).n == 0);
}

void test_wtwire(void) {
  test_wtwire_signal_put_uni();
  test_wtwire_signal_put_bidi();
  test_wtwire_signal_put_capacity();
  test_wtwire_qsid_put();
  test_wtwire_qsid_roundtrip();
  test_wtwire_qsid_take_malformed();
  test_wtwire_qsid_take_range();
  test_wtwire_get_parse_ok();
  test_wtwire_get_parse_reject();
  test_wtwire_get_put_roundtrip();
  test_wtwire_push_parse_ok();
  test_wtwire_push_head_put_roundtrip();
  test_wtwire_push_parse_reject();
  test_wtwire_basename();
}
