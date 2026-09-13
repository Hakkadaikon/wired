#include "app/qpack/qpack/dyntable.h"

#include "test.h"

/* Build a field from two C-string literals of the given lengths. */
static qpack_field dt_field(const char* n, usz nl, const char* v, usz vl) {
  qpack_field f = {
      wired_span_of((const u8*)n, nl), wired_span_of((const u8*)v, vl)};
  return f;
}

/* RFC 9204 3.2.1: entry_size = name_len + value_len + 32. */
static void test_insert_size(void) {
  qpack_dyn   t;
  qpack_field f1 = dt_field("abc", 3, "xy", 2);
  qpack_field f2 = dt_field("k", 1, "v", 1);
  qpack_dyn_init(&t, 4096);
  CHECK(qpack_dyn_insert(&t, &f1) == 1);
  CHECK(qpack_dyn_size(&t) == 3 + 2 + 32);
  CHECK(qpack_dyn_insert(&t, &f2) == 1);
  CHECK(qpack_dyn_size(&t) == (3 + 2 + 32) + (1 + 1 + 32));
}

/* RFC 9204 3.2.2: exceeding capacity evicts the oldest entry. */
static void test_evict_on_overflow(void) {
  qpack_dyn   t;
  qpack_field a = dt_field("a", 1, "1", 1);
  qpack_field b = dt_field("b", 1, "2", 1);
  qpack_field c = dt_field("c", 1, "3", 1);
  /* each entry: 1 + 1 + 32 = 34; capacity holds two but not three. */
  qpack_dyn_init(&t, 70);
  CHECK(qpack_dyn_insert(&t, &a) == 1);
  CHECK(qpack_dyn_insert(&t, &b) == 1);
  CHECK(qpack_dyn_insert(&t, &c) == 1);
  CHECK(qpack_dyn_size(&t) == 68);
  /* "a" (abs 0) evicted, "b","c" (abs 1,2) live. */
  CHECK(t.dropped == 1);
}

/* RFC 9204 3.2.2: an entry larger than capacity is rejected, table unchanged.
 */
static void test_too_big_rejected(void) {
  qpack_dyn   t;
  qpack_field f = dt_field("name", 4, "value", 5);
  qpack_dyn_init(&t, 40);
  CHECK(qpack_dyn_insert(&t, &f) == 0);
  CHECK(qpack_dyn_size(&t) == 0);
  CHECK(t.count == 0);
}

/* RFC 9204 4.3.1: a Set Dynamic Table Capacity at or below the advertised
 * SETTINGS_QPACK_MAX_TABLE_CAPACITY limit is valid. */
static void test_capacity_within_limit_accepted(void) {
  CHECK(qpack_capacity_within_limit(0, 0));
  CHECK(qpack_capacity_within_limit(100, 100));
  CHECK(qpack_capacity_within_limit(50, 100));
}

/* RFC 9204 4.3.1: a capacity exceeding the limit is rejected -- the caller
 * treats it as a connection error of type QPACK_ENCODER_STREAM_ERROR. */
static void test_capacity_over_limit_rejected(void) {
  CHECK(!qpack_capacity_within_limit(101, 100));
  CHECK(!qpack_capacity_within_limit(1, 0));
}

/* RFC 9204 3.2.2: "Whenever the dynamic table capacity is reduced ...
 * entries are evicted from the end of the dynamic table until the size of
 * the dynamic table is less than or equal to the new table capacity." Two
 * 34-byte entries (68 bytes) reduced to a 40-byte capacity must evict the
 * oldest one, leaving the table at or below 40. */
static void test_set_capacity_reduction_evicts(void) {
  qpack_dyn   t;
  qpack_field a = dt_field("a", 1, "1", 1);
  qpack_field b = dt_field("b", 1, "2", 1);
  qpack_dyn_init(&t, 4096);
  CHECK(qpack_dyn_insert(&t, &a) == 1);
  CHECK(qpack_dyn_insert(&t, &b) == 1);
  CHECK(qpack_dyn_size(&t) == 68);
  qpack_dyn_set_capacity(&t, 40);
  CHECK(qpack_dyn_size(&t) == 34); /* "a" evicted, "b" survives */
  CHECK(t.count == 1);
  CHECK(t.dropped == 1);
  CHECK(t.capacity == 40);
}

/* RFC 9204 3.2.2: "This mechanism can be used to completely clear entries
 * from the dynamic table by setting a capacity of 0." */
static void test_set_capacity_zero_clears_table(void) {
  qpack_dyn   t;
  qpack_field a = dt_field("a", 1, "1", 1);
  qpack_field b = dt_field("b", 1, "2", 1);
  qpack_dyn_init(&t, 4096);
  CHECK(qpack_dyn_insert(&t, &a) == 1);
  CHECK(qpack_dyn_insert(&t, &b) == 1);
  qpack_dyn_set_capacity(&t, 0);
  CHECK(qpack_dyn_size(&t) == 0);
  CHECK(t.count == 0);
  CHECK(t.dropped == 2);
  CHECK(t.capacity == 0);
}

/* Raising the capacity never evicts (make_room's over_capacity check stays
 * false): shrink to 34 (evicting "b", leaving only "a"), then raise back to
 * 4096 -- "a" must survive the raise untouched, and inserting "b" again
 * (which the shrunk capacity had no room for) now succeeds. */
static void test_set_capacity_raise_does_not_evict(void) {
  qpack_dyn   t;
  qpack_field a = dt_field("a", 1, "1", 1);
  qpack_field b = dt_field("b", 1, "2", 1);
  qpack_dyn_init(&t, 4096);
  CHECK(qpack_dyn_insert(&t, &a) == 1);
  CHECK(qpack_dyn_insert(&t, &b) == 1);
  qpack_dyn_set_capacity(&t, 34);
  CHECK(qpack_dyn_size(&t) == 34); /* "a" evicted, "b" survives */
  CHECK(t.dropped == 1);
  qpack_dyn_set_capacity(&t, 4096); /* raise: must not evict "b" */
  CHECK(qpack_dyn_size(&t) == 34);
  CHECK(t.dropped == 1);
  CHECK(qpack_dyn_insert(&t, &a) == 1); /* now fits alongside "b" */
  CHECK(qpack_dyn_size(&t) == 68);
}

/* Pinning: RFC 9204 7.3 -- QPACK memory is bounded twice over: the
 * compile-time ring size (QPACK_DYN_MAX_ENTRIES) and the peer-controlled
 * capacity value. Filling the ring past its slot count must never grow it
 * or corrupt older entries (V-0475). */
static void test_qpack_dyntable_bounded_by_max_entries(void) {
  qpack_dyn t;
  /* one-byte name/value entries cost 1+1+32=34 bytes each; a capacity of
   * QPACK_DYN_MAX_ENTRIES*34 lets every ring slot hold one live entry. */
  qpack_dyn_init(&t, QPACK_DYN_MAX_ENTRIES * 34);
  for (usz i = 0; i < QPACK_DYN_MAX_ENTRIES + 8; i++) {
    u8          nb = (u8)('a' + (i % 26));
    qpack_field f  = dt_field((const char*)&nb, 1, "1", 1);
    /* the ring's slot count is the hard ceiling: once every slot is live
     * an insert is refused (0), never wrapped over an older live entry. */
    CHECK(qpack_dyn_insert(&t, &f) == (i < QPACK_DYN_MAX_ENTRIES));
    CHECK(t.count <= QPACK_DYN_MAX_ENTRIES);
  }
  CHECK(t.count == QPACK_DYN_MAX_ENTRIES);
}

/* Pinning: CVE-2026-42530-class UAF -- the dynamic table is a fixed-size
 * struct embedded in the connection slot, never independently freed; a
 * table that has evicted entries down to empty (simulating stream/request
 * teardown churn) must remain safely insertable afterward, never dangling
 * (V-0434). */
static void test_qpack_dyntable_survives_stream_teardown(void) {
  qpack_dyn   t;
  qpack_field a = dt_field("a", 1, "1", 1);
  qpack_dyn_init(&t, 4096);
  CHECK(qpack_dyn_insert(&t, &a) == 1);
  /* simulate teardown: capacity dropped to 0 clears every entry. */
  qpack_dyn_set_capacity(&t, 0);
  CHECK(t.count == 0);
  /* the table is still a valid, live struct -- a new stream/request can
   * insert into it immediately without any re-initialization. */
  qpack_dyn_set_capacity(&t, 4096);
  CHECK(qpack_dyn_insert(&t, &a) == 1);
  CHECK(t.count == 1);
}

void test_dyntable(void) {
  test_insert_size();
  test_evict_on_overflow();
  test_too_big_rejected();
  test_capacity_within_limit_accepted();
  test_capacity_over_limit_rejected();
  test_set_capacity_reduction_evicts();
  test_set_capacity_zero_clears_table();
  test_set_capacity_raise_does_not_evict();
  test_qpack_dyntable_bounded_by_max_entries();
  test_qpack_dyntable_survives_stream_teardown();
}
