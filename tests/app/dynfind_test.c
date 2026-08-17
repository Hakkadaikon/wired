#include "app/qpack/qpack/dynfind.h"

#include "test.h"

/* Build a one-byte-name, one-byte-value field from two C-string literals. */
static qpack_field df_field(const char* n, const char* v) {
  qpack_field f = {
      wired_span_of((const u8*)n, 1), wired_span_of((const u8*)v, 1)};
  return f;
}

static void seed(qpack_dyn* t) {
  qpack_field a = df_field("a", "1");
  qpack_field b = df_field("b", "2");
  qpack_dyn_init(t, 4096);
  qpack_dyn_insert(t, &a);
  qpack_dyn_insert(t, &b);
}

/* RFC 9204 2.1: a full name+value match reports value_matched = 1. */
static void test_find_full(void) {
  qpack_dyn   t;
  qpack_field q = df_field("b", "2");
  qpack_match m;
  seed(&t);
  CHECK(qpack_dyn_find(&t, &q, &m) == 1);
  CHECK(m.abs_index == 1 && m.value_matched == 1);
}

/* RFC 9204 2.1: a name-only match reports value_matched = 0. */
static void test_find_name_only(void) {
  qpack_dyn   t;
  qpack_field q = df_field("a", "x");
  qpack_match m;
  seed(&t);
  CHECK(qpack_dyn_find(&t, &q, &m) == 1);
  CHECK(m.abs_index == 0 && m.value_matched == 0);
}

/* RFC 9204 2.1: full match is preferred even if a name-only entry comes first.
 */
static void test_find_prefers_full(void) {
  qpack_dyn   t;
  qpack_field hx = df_field("h", "x");
  qpack_field hy = df_field("h", "y");
  qpack_match m;
  qpack_dyn_init(&t, 4096);
  qpack_dyn_insert(&t, &hx);
  qpack_dyn_insert(&t, &hy);
  CHECK(qpack_dyn_find(&t, &hy, &m) == 1);
  CHECK(m.abs_index == 1 && m.value_matched == 1);
}

/* RFC 9204 2.1: no name match returns 0. */
static void test_find_miss(void) {
  qpack_dyn   t;
  qpack_field q = df_field("z", "9");
  qpack_match m;
  seed(&t);
  CHECK(qpack_dyn_find(&t, &q, &m) == 0);
}

void test_dynfind(void) {
  test_find_full();
  test_find_name_only();
  test_find_prefers_full();
  test_find_miss();
}
