#include "app/qpack/qpack/dynfind.h"

#include "test.h"

static void seed(quic_qpack_dyn *t) {
  quic_qpack_dyn_init(t, 4096);
  quic_qpack_dyn_insert(t, (const u8 *)"a", 1, (const u8 *)"1", 1);
  quic_qpack_dyn_insert(t, (const u8 *)"b", 1, (const u8 *)"2", 1);
}

/* RFC 9204 2.1: a full name+value match reports value_matched = 1. */
static void test_find_full(void) {
  quic_qpack_dyn t;
  seed(&t);
  u64 idx;
  int vm;
  CHECK(
      quic_qpack_dyn_find(
          &t, (const u8 *)"b", 1, (const u8 *)"2", 1, &idx, &vm) == 1);
  CHECK(idx == 1 && vm == 1);
}

/* RFC 9204 2.1: a name-only match reports value_matched = 0. */
static void test_find_name_only(void) {
  quic_qpack_dyn t;
  seed(&t);
  u64 idx;
  int vm;
  CHECK(
      quic_qpack_dyn_find(
          &t, (const u8 *)"a", 1, (const u8 *)"x", 1, &idx, &vm) == 1);
  CHECK(idx == 0 && vm == 0);
}

/* RFC 9204 2.1: full match is preferred even if a name-only entry comes first.
 */
static void test_find_prefers_full(void) {
  quic_qpack_dyn t;
  quic_qpack_dyn_init(&t, 4096);
  quic_qpack_dyn_insert(&t, (const u8 *)"h", 1, (const u8 *)"x", 1);
  quic_qpack_dyn_insert(&t, (const u8 *)"h", 1, (const u8 *)"y", 1);
  u64 idx;
  int vm;
  CHECK(
      quic_qpack_dyn_find(
          &t, (const u8 *)"h", 1, (const u8 *)"y", 1, &idx, &vm) == 1);
  CHECK(idx == 1 && vm == 1);
}

/* RFC 9204 2.1: no name match returns 0. */
static void test_find_miss(void) {
  quic_qpack_dyn t;
  seed(&t);
  u64 idx;
  int vm;
  CHECK(
      quic_qpack_dyn_find(
          &t, (const u8 *)"z", 1, (const u8 *)"9", 1, &idx, &vm) == 0);
}

void test_dynfind(void) {
  test_find_full();
  test_find_name_only();
  test_find_prefers_full();
  test_find_miss();
}
