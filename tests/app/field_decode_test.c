#include "app/qpack/qpackdyn/field_decode.h"

#include "app/qpack/qpack/dynfind.h"
#include "app/qpack/qpack/dyntable.h"
#include "app/qpack/qpack/relindex.h"
#include "app/qpack/qpackdyn/cstr.h"
#include "app/qpack/qpackdyn/field_encode.h"
#include "test.h"

#define eq_len(s) quic_qdyn_cstr_len(s)

static int eq(const u8 *a, usz alen, const char *b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

/* Insert (name, value), encode the dynamic reference relative to base, then
 * decode it back and assert the borrowed (name, value) round-trips. */
static void qd_roundtrip(
    quic_qpack_dyn *t, const char *name, const char *value) {
  u8        fs[8];
  usz       fs_len = 0, consumed = 0;
  u64       abs, base, rel;
  int       matched;
  const u8 *dn, *dv;
  usz       dnl, dvl;

  CHECK(quic_qpack_dyn_insert(
      t, (const u8 *)name, eq_len(name), (const u8 *)value, eq_len(value)));
  base = t->dropped + t->count;
  CHECK(quic_qpack_dyn_find(
      t, (const u8 *)name, eq_len(name), (const u8 *)value, eq_len(value), &abs,
      &matched));
  rel = base - abs - 1;
  CHECK(quic_qdyn_indexed_dynamic(rel, fs, sizeof(fs), &fs_len));
  CHECK(quic_qdyn_decode_field(
      t, base, fs, fs_len, 0, &dn, &dnl, &dv, &dvl, &consumed));
  CHECK(consumed == fs_len);
  CHECK(eq(dn, dnl, name, eq_len(name)));
  CHECK(eq(dv, dvl, value, eq_len(value)));
}

static void test_dynamic_roundtrip(void) {
  quic_qpack_dyn t;
  quic_qpack_dyn_init(&t, 4096);
  qd_roundtrip(&t, "x-a", "1");
  qd_roundtrip(&t, "x-b", "two");
  /* The older entry still resolves after a second insert (base advanced). */
  {
    u8        fs[8];
    usz       fs_len = 0, consumed = 0;
    u64       base = t.dropped + t.count;
    const u8 *dn, *dv;
    usz       dnl, dvl;
    /* abs 0 ("x-a") relative to base 2 is rel = 1. */
    CHECK(quic_qdyn_indexed_dynamic(1, fs, sizeof(fs), &fs_len));
    CHECK(quic_qdyn_decode_field(
        &t, base, fs, fs_len, 0, &dn, &dnl, &dv, &dvl, &consumed));
    CHECK(eq(dn, dnl, "x-a", 3) && eq(dv, dvl, "1", 1));
  }
}

/* RFC 9204 4.5.2: a static reference (T=1) resolves from the static table.
 * Static index 17 is :method GET. */
static void test_static_reference(void) {
  quic_qpack_dyn t;
  u8             fs[2]    = {0xD1, 0x00}; /* 1Tiiiiii, T=1, index 17 */
  usz            consumed = 0;
  const u8      *dn, *dv;
  usz            dnl, dvl;
  quic_qpack_dyn_init(&t, 256);
  CHECK(
      quic_qdyn_decode_field(&t, 0, fs, 1, 0, &dn, &dnl, &dv, &dvl, &consumed));
  CHECK(consumed == 1);
  CHECK(eq(dn, dnl, ":method", 7) && eq(dv, dvl, "GET", 3));
}

/* A first byte without bit 7 is not an indexed field line. */
static void test_non_indexed_reject(void) {
  quic_qpack_dyn t;
  u8             fs[1]    = {0x20};
  usz            consumed = 99;
  const u8      *dn, *dv;
  usz            dnl, dvl;
  quic_qpack_dyn_init(&t, 256);
  CHECK(
      quic_qdyn_decode_field(
          &t, 0, fs, 1, 0, &dn, &dnl, &dv, &dvl, &consumed) == 0);
}

/* A dynamic index past the live window resolves to no entry. */
static void test_dynamic_miss(void) {
  quic_qpack_dyn t;
  u8             fs[2];
  usz            fs_len = 0, consumed = 0;
  const u8      *dn, *dv;
  usz            dnl, dvl;
  quic_qpack_dyn_init(&t, 256);
  CHECK(quic_qpack_dyn_insert(&t, (const u8 *)"a", 1, (const u8 *)"b", 1));
  /* base 1, rel 5 -> abs underflow / absent entry. */
  CHECK(quic_qdyn_indexed_dynamic(5, fs, sizeof(fs), &fs_len));
  CHECK(
      quic_qdyn_decode_field(
          &t, 1, fs, fs_len, 0, &dn, &dnl, &dv, &dvl, &consumed) == 0);
}

void test_qpackdyn_field_decode(void) {
  test_dynamic_roundtrip();
  test_static_reference();
  test_non_indexed_reject();
  test_dynamic_miss();
}
