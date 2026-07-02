#include "app/qpack/qpack/dynfind.h"

#include "test.h"

/* Build a one-byte-name, one-byte-value field from two C-string literals. */
static quic_qpack_field df_field(const char *n, const char *v) {
  quic_qpack_field f = {
      quic_span_of((const u8 *)n, 1), quic_span_of((const u8 *)v, 1)};
  return f;
}

static void seed(quic_qpack_dyn *t) {
  quic_qpack_field a = df_field("a", "1");
  quic_qpack_field b = df_field("b", "2");
  quic_qpack_dyn_init(t, 4096);
  quic_qpack_dyn_insert(t, &a);
  quic_qpack_dyn_insert(t, &b);
}

/* RFC 9204 2.1: a full name+value match reports value_matched = 1. */
static void test_find_full(void) {
  quic_qpack_dyn   t;
  quic_qpack_field q = df_field("b", "2");
  quic_qpack_match m;
  seed(&t);
  CHECK(quic_qpack_dyn_find(&t, &q, &m) == 1);
  CHECK(m.abs_index == 1 && m.value_matched == 1);
}

/* RFC 9204 2.1: a name-only match reports value_matched = 0. */
static void test_find_name_only(void) {
  quic_qpack_dyn   t;
  quic_qpack_field q = df_field("a", "x");
  quic_qpack_match m;
  seed(&t);
  CHECK(quic_qpack_dyn_find(&t, &q, &m) == 1);
  CHECK(m.abs_index == 0 && m.value_matched == 0);
}

/* RFC 9204 2.1: full match is preferred even if a name-only entry comes first.
 */
static void test_find_prefers_full(void) {
  quic_qpack_dyn   t;
  quic_qpack_field hx = df_field("h", "x");
  quic_qpack_field hy = df_field("h", "y");
  quic_qpack_match m;
  quic_qpack_dyn_init(&t, 4096);
  quic_qpack_dyn_insert(&t, &hx);
  quic_qpack_dyn_insert(&t, &hy);
  CHECK(quic_qpack_dyn_find(&t, &hy, &m) == 1);
  CHECK(m.abs_index == 1 && m.value_matched == 1);
}

/* RFC 9204 2.1: no name match returns 0. */
static void test_find_miss(void) {
  quic_qpack_dyn   t;
  quic_qpack_field q = df_field("z", "9");
  quic_qpack_match m;
  seed(&t);
  CHECK(quic_qpack_dyn_find(&t, &q, &m) == 0);
}

void test_dynfind(void) {
  test_find_full();
  test_find_name_only();
  test_find_prefers_full();
  test_find_miss();
}
