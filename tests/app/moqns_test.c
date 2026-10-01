#include "app/moqt/ns/moqns.h"

#include "app/moqt/vi/moqvi.h"
#include "moqt_golden.h"
#include "test.h"

/* draft-ietf-moq-transport-19 namespace message codecs: SUBSCRIBE_NAMESPACE
 * (10.18), PUBLISH_NAMESPACE (10.15), NAMESPACE (10.16), NAMESPACE_DONE
 * (10.17) and the Track Namespace bounds (2.4.1). Wire bytes for the
 * round trips come from tests/app/moqt_golden.h. */

/* Frames a golden message with moqctl_peek_type and returns its body. */
static wired_span moqns_t_body(const u8* msg, usz n, u64 want_type) {
  usz        off  = 0;
  u64        type = 0;
  wired_span body = wired_span_of(msg, 0);
  CHECK(
      moqctl_peek_type(wired_span_of(msg, n), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(type == want_type);
  CHECK(off == n);
  return body;
}

static void moqns_t_same(const u8* out, usz n, wired_span want) {
  CHECK(n == want.n);
  for (usz i = 0; i < n && i < want.n; i++) CHECK(out[i] == want.p[i]);
}

static void test_moqns_subscribe_golden(void) {
  wired_span body = moqns_t_body(
      g_moqt_ctl_subscribe_namespace_basic,
      G_MOQT_CTL_SUBSCRIBE_NAMESPACE_BASIC_LEN, MOQNS_T_SUBSCRIBE_NAMESPACE);
  moqns_req m;
  u8        out[MOQCTL_MAX_MSG_LEN];
  usz       n = 0;
  CHECK(body.n == G_MOQT_CTL_SUBSCRIBE_NAMESPACE_BASIC_MSG_LEN);
  if (moqns_subscribe_take(body, &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.request_id == 6);
  CHECK(m.ns.n == 1);
  CHECK(m.ns.fields[0].n == 4);
  CHECK(m.ns.fields[0].p[0] == 'c');
  CHECK(m.params.n == 0);
  CHECK(moqns_req_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqns_t_same(out, n, body);
}

static void test_moqns_publish_golden(void) {
  wired_span body = moqns_t_body(
      g_moqt_ctl_publish_namespace_basic,
      G_MOQT_CTL_PUBLISH_NAMESPACE_BASIC_LEN, MOQNS_T_PUBLISH_NAMESPACE);
  moqns_req m;
  u8        out[MOQCTL_MAX_MSG_LEN];
  usz       n = 0;
  if (moqns_publish_take(body, &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.request_id == 8);
  CHECK(m.ns.n == 2);
  CHECK(m.ns.fields[1].n == 5);
  CHECK(m.ns.fields[1].p[4] == '1');
  CHECK(moqns_req_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqns_t_same(out, n, body);
}

static void moqns_t_suffix_golden(const u8* msg, usz len, u64 type) {
  wired_span body = moqns_t_body(msg, len, type);
  moqctl_ns  ns;
  u8         out[MOQCTL_MAX_MSG_LEN];
  usz        n = 0;
  if (moqns_suffix_take(body, &ns) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(ns.n == 1);
  CHECK(ns.fields[0].n == 5);
  CHECK(ns.fields[0].p[0] == 'r');
  CHECK(moqctl_ns_put(wired_mspan_of(out, sizeof out), &n, &ns));
  moqns_t_same(out, n, body);
}

static void test_moqns_suffix_golden(void) {
  moqns_t_suffix_golden(
      g_moqt_ctl_namespace_basic, G_MOQT_CTL_NAMESPACE_BASIC_LEN,
      MOQNS_T_NAMESPACE);
  moqns_t_suffix_golden(
      g_moqt_ctl_namespace_done_basic, G_MOQT_CTL_NAMESPACE_DONE_BASIC_LEN,
      MOQNS_T_NAMESPACE_DONE);
}

/* 10: a body whose Length cuts a field short, or leaves bytes over, is a
 * Length mismatch. */
static void test_moqns_length_mismatch(void) {
  const u8* b = g_moqt_ctl_publish_namespace_basic + 3;
  usz       n = G_MOQT_CTL_PUBLISH_NAMESPACE_BASIC_MSG_LEN;
  u8        extra[G_MOQT_CTL_PUBLISH_NAMESPACE_BASIC_MSG_LEN + 1];
  moqns_req m;
  moqctl_ns ns;
  for (usz cut = 0; cut < n; cut++)
    CHECK(moqns_publish_take(wired_span_of(b, cut), &m) == MOQCTL_VIOLATION);
  for (usz i = 0; i < n; i++) extra[i] = b[i];
  extra[n] = 0;
  CHECK(
      moqns_publish_take(wired_span_of(extra, n + 1), &m) == MOQCTL_VIOLATION);
  CHECK(moqns_suffix_take(wired_span_of(b, 0), &ns) == MOQCTL_VIOLATION);
  CHECK(
      moqns_suffix_take(
          wired_span_of(g_moqt_ctl_namespace_basic + 3, 6), &ns) ==
      MOQCTL_VIOLATION);
}

/* 2.4.1: a zero-length field and more than 32 fields are violations; an
 * empty suffix (0 fields) and exactly 32 fields are fine. */
static void test_moqns_field_rules(void) {
  static const u8 zero_len[] = {0x01, 0x00};
  u8              many[1 + 33 * 2];
  moqctl_ns       ns;
  static const u8 empty[] = {0x00};
  CHECK(
      moqns_suffix_take(wired_span_of(zero_len, sizeof zero_len), &ns) ==
      MOQCTL_VIOLATION);
  CHECK(moqns_suffix_take(wired_span_of(empty, 1), &ns) == MOQCTL_OK);
  CHECK(ns.n == 0);
  for (usz i = 0; i < 33; i++) {
    many[1 + 2 * i] = 1;
    many[2 + 2 * i] = 'x';
  }
  many[0] = 32;
  CHECK(moqns_suffix_take(wired_span_of(many, 1 + 32 * 2), &ns) == MOQCTL_OK);
  CHECK(ns.n == MOQCTL_MAX_NS_FIELDS);
  many[0] = 33;
  CHECK(
      moqns_suffix_take(wired_span_of(many, sizeof many), &ns) ==
      MOQCTL_VIOLATION);
}

/* 2.4.1: the namespace length (sum of field lengths) may be 4,096 bytes,
 * not 4,097. Two fields so the bound is the sum, not one field. */
static void test_moqns_total_bound(void) {
  static u8   b[1 + 2 + 4095 + 1 + 2]; /* count, len 4095, field, len, 2 */
  usz         n = 0;
  moqctl_ns   ns;
  wired_mspan m = wired_mspan_of(b, sizeof b);
  for (usz i = 0; i < sizeof b; i++) b[i] = 'y';
  b[n++] = 2;
  CHECK(moqvi_put(m, &n, 4095));
  n += 4095;
  b[n++] = 1;
  CHECK(moqns_suffix_take(wired_span_of(b, n + 1), &ns) == MOQCTL_OK);
  CHECK(moqctl_ns_bytelen(&ns) == MOQCTL_MAX_FTN_LEN);
  b[n - 1] = 2;
  CHECK(moqns_suffix_take(wired_span_of(b, n + 2), &ns) == MOQCTL_VIOLATION);
}

/* 10.2.1: SUBSCRIBE_NAMESPACE admits AUTHORIZATION_TOKEN but not FORWARD
 * (10.2.17 does not list it). */
static void test_moqns_param_scope(void) {
  static const u8 fwd[]  = {0x01, 0x01, 0x01, 'a', 0x01, 0x10, 0x01};
  static const u8 auth[] = {0x01, 0x01, 0x01, 'a', 0x01,
                            0x03, 0x02, 0x03, 0x00};
  moqns_req       m;
  CHECK(
      moqns_subscribe_take(wired_span_of(fwd, sizeof fwd), &m) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqns_subscribe_take(wired_span_of(auth, sizeof auth), &m) == MOQCTL_OK);
  CHECK(m.params.n == 1);
  CHECK(moqns_publish_take(wired_span_of(auth, sizeof auth), &m) == MOQCTL_OK);
}

/* 1.4.1 MOQT varint size boundaries on Request ID: 127 | 128 (1 -> 2
 * bytes) and 16383 | 16384 (2 -> 3 bytes) round trip with minimal size. */
static void moqns_t_rid(u64 rid, usz want_len) {
  moqns_req m = {0};
  moqns_req d;
  u8        out[16];
  usz       n  = 0;
  m.request_id = rid;
  CHECK(moqns_req_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(n == want_len + 2);
  CHECK(moqns_publish_take(wired_span_of(out, n), &d) == MOQCTL_OK);
  CHECK(d.request_id == rid);
}

static void test_moqns_varint_boundaries(void) {
  moqns_t_rid(127, 1);
  moqns_t_rid(128, 2);
  moqns_t_rid(16383, 2);
  moqns_t_rid(16384, 3);
}

static void test_moqns_encode_no_room(void) {
  moqns_req m = {0};
  u8        out[2];
  usz       n = 0;
  CHECK(!moqns_req_encode(wired_mspan_of(out, sizeof out), &n, &m));
}

/* Encodes ns, appends one stray byte, and expects moqctl_ns_take to
 * stop right before it with the same fields (2.4.1). Returns the encoded
 * length. */
static usz moqns_t_tuple_rt(const moqctl_ns* ns, u8* buf, usz cap) {
  usz       n   = 0;
  usz       off = 0;
  moqctl_ns d;
  CHECK(moqctl_ns_put(wired_mspan_of(buf, cap), &n, ns));
  buf[n] = 0xaa;
  CHECK(moqctl_ns_take(wired_span_of(buf, n + 1), &off, &d) == MOQCTL_OK);
  CHECK(off == n && d.n == ns->n);
  for (usz i = 0; i < d.n && i < ns->n; i++)
    CHECK(d.fields[i].n == ns->fields[i].n);
  return n;
}

/* Boundaries of the tuple: 0 fields, one 1-byte field, 32 fields, a
 * 4,096-byte field (2-byte Field Length 90 00), Field Length 127 | 128
 * (MOQT varint 1 -> 2 bytes). */
static void test_moqns_tuple_roundtrip(void) {
  static u8       big[MOQCTL_MAX_FTN_LEN];
  static u8       buf[16 + MOQCTL_MAX_FTN_LEN];
  static const u8 a[] = {'a'};
  moqctl_ns       ns  = {0};
  CHECK(moqns_t_tuple_rt(&ns, buf, sizeof buf) == 1 && buf[0] == 0);
  ns.n         = 1;
  ns.fields[0] = wired_span_of(a, 1);
  CHECK(moqns_t_tuple_rt(&ns, buf, sizeof buf) == 3);
  CHECK(buf[0] == 0x01 && buf[1] == 0x01 && buf[2] == 'a');
  ns.n = MOQCTL_MAX_NS_FIELDS;
  for (usz i = 0; i < ns.n; i++) ns.fields[i] = wired_span_of(a, 1);
  CHECK(moqns_t_tuple_rt(&ns, buf, sizeof buf) == 1 + 32 * 2);
  ns.n         = 1;
  ns.fields[0] = wired_span_of(big, MOQCTL_MAX_FTN_LEN);
  CHECK(moqns_t_tuple_rt(&ns, buf, sizeof buf) == 3 + MOQCTL_MAX_FTN_LEN);
  CHECK(buf[1] == 0x90 && buf[2] == 0x00);
  ns.fields[0] = wired_span_of(big, 127);
  CHECK(moqns_t_tuple_rt(&ns, buf, sizeof buf) == 2 + 127);
  ns.fields[0] = wired_span_of(big, 128);
  CHECK(moqns_t_tuple_rt(&ns, buf, sizeof buf) == 3 + 128);
}

/* 1.4.1: non-minimal varints are valid on receive (count 1 as 80 01). */
static void test_moqns_tuple_nonminimal(void) {
  static const u8 b[] = {0x80, 0x01, 0x80, 0x01, 'a'};
  usz             off = 0;
  moqctl_ns       ns;
  CHECK(moqctl_ns_take(wired_span_of(b, sizeof b), &off, &ns) == MOQCTL_OK);
  CHECK(off == sizeof b && ns.n == 1 && ns.fields[0].p[0] == 'a');
}

/* 2.4.1 rejections: 33 fields (before any field is read), a 2^64-1
 * count, a zero-length field, 4,096 + 1 bytes over two fields; a field
 * cut short needs more bytes (stream) / is a Length mismatch (body). */
static void test_moqns_tuple_rejects(void) {
  static const u8 c33[]  = {0x21};
  static const u8 cmax[] = {0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff};
  static const u8 z[]    = {0x01, 0x00};
  static const u8 cut[]  = {0x01, 0x02, 0x61};
  static u8       over[1 + 2 + MOQCTL_MAX_FTN_LEN + 2];
  wired_mspan     m   = wired_mspan_of(over, sizeof over);
  usz             n   = 0;
  usz             off = 0;
  moqctl_ns       ns;
  CHECK(moqctl_ns_take(wired_span_of(c33, 1), &off, &ns) == MOQCTL_VIOLATION);
  CHECK(
      moqctl_ns_take(wired_span_of(cmax, sizeof cmax), &off, &ns) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqctl_ns_take(wired_span_of(z, sizeof z), &off, &ns) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqctl_ns_take(wired_span_of(cut, sizeof cut), &off, &ns) ==
      MOQCTL_INSUFFICIENT);
  CHECK(off == 0);
  CHECK(
      moqns_suffix_take(wired_span_of(cut, sizeof cut), &ns) ==
      MOQCTL_VIOLATION);
  over[n++] = 2;
  CHECK(moqvi_put(m, &n, MOQCTL_MAX_FTN_LEN));
  n += MOQCTL_MAX_FTN_LEN;
  over[n++] = 1;
  over[n++] = 'z';
  CHECK(moqctl_ns_take(wired_span_of(over, n), &off, &ns) == MOQCTL_VIOLATION);
}

void test_moqns(void) {
  test_moqns_subscribe_golden();
  test_moqns_publish_golden();
  test_moqns_suffix_golden();
  test_moqns_length_mismatch();
  test_moqns_field_rules();
  test_moqns_total_bound();
  test_moqns_param_scope();
  test_moqns_varint_boundaries();
  test_moqns_encode_no_room();
  test_moqns_tuple_roundtrip();
  test_moqns_tuple_nonminimal();
  test_moqns_tuple_rejects();
}
