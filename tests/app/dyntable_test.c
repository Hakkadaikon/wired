#include "app/qpack/qpack/dyntable.h"

#include "test.h"

/* Build a field from two C-string literals of the given lengths. */
static quic_qpack_field dt_field(const char* n, usz nl, const char* v, usz vl) {
  quic_qpack_field f = {
      quic_span_of((const u8*)n, nl), quic_span_of((const u8*)v, vl)};
  return f;
}

/* RFC 9204 3.2.1: entry_size = name_len + value_len + 32. */
static void test_insert_size(void) {
  quic_qpack_dyn   t;
  quic_qpack_field f1 = dt_field("abc", 3, "xy", 2);
  quic_qpack_field f2 = dt_field("k", 1, "v", 1);
  quic_qpack_dyn_init(&t, 4096);
  CHECK(quic_qpack_dyn_insert(&t, &f1) == 1);
  CHECK(quic_qpack_dyn_size(&t) == 3 + 2 + 32);
  CHECK(quic_qpack_dyn_insert(&t, &f2) == 1);
  CHECK(quic_qpack_dyn_size(&t) == (3 + 2 + 32) + (1 + 1 + 32));
}

/* RFC 9204 3.2.2: exceeding capacity evicts the oldest entry. */
static void test_evict_on_overflow(void) {
  quic_qpack_dyn   t;
  quic_qpack_field a = dt_field("a", 1, "1", 1);
  quic_qpack_field b = dt_field("b", 1, "2", 1);
  quic_qpack_field c = dt_field("c", 1, "3", 1);
  /* each entry: 1 + 1 + 32 = 34; capacity holds two but not three. */
  quic_qpack_dyn_init(&t, 70);
  CHECK(quic_qpack_dyn_insert(&t, &a) == 1);
  CHECK(quic_qpack_dyn_insert(&t, &b) == 1);
  CHECK(quic_qpack_dyn_insert(&t, &c) == 1);
  CHECK(quic_qpack_dyn_size(&t) == 68);
  /* "a" (abs 0) evicted, "b","c" (abs 1,2) live. */
  CHECK(t.dropped == 1);
}

/* RFC 9204 3.2.2: an entry larger than capacity is rejected, table unchanged.
 */
static void test_too_big_rejected(void) {
  quic_qpack_dyn   t;
  quic_qpack_field f = dt_field("name", 4, "value", 5);
  quic_qpack_dyn_init(&t, 40);
  CHECK(quic_qpack_dyn_insert(&t, &f) == 0);
  CHECK(quic_qpack_dyn_size(&t) == 0);
  CHECK(t.count == 0);
}

void test_dyntable(void) {
  test_insert_size();
  test_evict_on_overflow();
  test_too_big_rejected();
}
