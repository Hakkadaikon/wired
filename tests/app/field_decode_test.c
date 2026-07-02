#include "app/qpack/qpackdyn/field_decode.h"

#include "app/qpack/qpack/dynfind.h"
#include "app/qpack/qpack/dyntable.h"
#include "app/qpack/qpack/relindex.h"
#include "app/qpack/qpackdyn/cstr.h"
#include "app/qpack/qpackdyn/field_encode.h"
#include "test.h"

#define eq_len(s) quic_qdyn_cstr_len(s)

static int eq(quic_span a, const char *b, usz blen) {
  if (a.n != blen) return 0;
  for (usz i = 0; i < a.n; i++)
    if (a.p[i] != (u8)b[i]) return 0;
  return 1;
}

static quic_qpack_field fd_field(const char *name, const char *value) {
  quic_qpack_field f = {
      quic_span_of((const u8 *)name, eq_len(name)),
      quic_span_of((const u8 *)value, eq_len(value))};
  return f;
}

/* Insert (name, value), encode the dynamic reference relative to base, then
 * decode it back and assert the borrowed (name, value) round-trips. */
static void qd_roundtrip(
    quic_qpack_dyn *t, const char *name, const char *value) {
  u8               fs[8];
  quic_obuf        ob       = quic_obuf_of(fs, sizeof(fs));
  usz              consumed = 0;
  u64              base, rel;
  quic_qpack_field f = fd_field(name, value);
  quic_qpack_match m;
  quic_qpack_field d;

  CHECK(quic_qpack_dyn_insert(t, &f));
  base = t->dropped + t->count;
  CHECK(quic_qpack_dyn_find(t, &f, &m));
  rel = base - m.abs_index - 1;
  CHECK(quic_qdyn_indexed_dynamic(rel, &ob));
  quic_qdyn_src src = {t, base, quic_span_of(fs, ob.len)};
  CHECK(quic_qdyn_decode_field(&src, &d, &consumed));
  CHECK(consumed == ob.len);
  CHECK(eq(d.name, name, eq_len(name)));
  CHECK(eq(d.value, value, eq_len(value)));
}

static void test_dynamic_roundtrip(void) {
  quic_qpack_dyn t;
  quic_qpack_dyn_init(&t, 4096);
  qd_roundtrip(&t, "x-a", "1");
  qd_roundtrip(&t, "x-b", "two");
  /* The older entry still resolves after a second insert (base advanced). */
  {
    u8               fs[8];
    quic_obuf        ob       = quic_obuf_of(fs, sizeof(fs));
    usz              consumed = 0;
    u64              base     = t.dropped + t.count;
    quic_qpack_field d;
    /* abs 0 ("x-a") relative to base 2 is rel = 1. */
    CHECK(quic_qdyn_indexed_dynamic(1, &ob));
    quic_qdyn_src src = {&t, base, quic_span_of(fs, ob.len)};
    CHECK(quic_qdyn_decode_field(&src, &d, &consumed));
    CHECK(eq(d.name, "x-a", 3) && eq(d.value, "1", 1));
  }
}

/* RFC 9204 4.5.2: a static reference (T=1) resolves from the static table.
 * Static index 17 is :method GET. */
static void test_static_reference(void) {
  quic_qpack_dyn   t;
  u8               fs[2]    = {0xD1, 0x00}; /* 1Tiiiiii, T=1, index 17 */
  usz              consumed = 0;
  quic_qpack_field d;
  quic_qpack_dyn_init(&t, 256);
  quic_qdyn_src src = {&t, 0, quic_span_of(fs, 1)};
  CHECK(quic_qdyn_decode_field(&src, &d, &consumed));
  CHECK(consumed == 1);
  CHECK(eq(d.name, ":method", 7) && eq(d.value, "GET", 3));
}

/* A first byte without bit 7 is not an indexed field line. */
static void test_non_indexed_reject(void) {
  quic_qpack_dyn   t;
  u8               fs[1]    = {0x20};
  usz              consumed = 99;
  quic_qpack_field d;
  quic_qpack_dyn_init(&t, 256);
  quic_qdyn_src src = {&t, 0, quic_span_of(fs, 1)};
  CHECK(quic_qdyn_decode_field(&src, &d, &consumed) == 0);
}

/* A dynamic index past the live window resolves to no entry. */
static void test_dynamic_miss(void) {
  quic_qpack_dyn   t;
  u8               fs[2];
  quic_obuf        ob       = quic_obuf_of(fs, sizeof(fs));
  usz              consumed = 0;
  quic_qpack_field f        = fd_field("a", "b");
  quic_qpack_field d;
  quic_qpack_dyn_init(&t, 256);
  CHECK(quic_qpack_dyn_insert(&t, &f));
  /* base 1, rel 5 -> abs underflow / absent entry. */
  CHECK(quic_qdyn_indexed_dynamic(5, &ob));
  quic_qdyn_src src = {&t, 1, quic_span_of(fs, ob.len)};
  CHECK(quic_qdyn_decode_field(&src, &d, &consumed) == 0);
}

void test_qpackdyn_field_decode(void) {
  test_dynamic_roundtrip();
  test_static_reference();
  test_non_indexed_reject();
  test_dynamic_miss();
}
