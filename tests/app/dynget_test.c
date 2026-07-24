#include "app/qpack/qpack/dynget.h"

#include "test.h"

/* Build a field from two C-string literals of the given lengths. */
static quic_qpack_field dg_field(const char* n, usz nl, const char* v, usz vl) {
  quic_qpack_field f = {
      quic_span_of((const u8*)n, nl), quic_span_of((const u8*)v, vl)};
  return f;
}

/* RFC 9204 3.2.4: a live absolute index resolves to its entry. */
static void test_get_live(void) {
  quic_qpack_dyn   t;
  quic_qpack_field a = dg_field("a", 1, "1", 1);
  quic_qpack_field b = dg_field("bb", 2, "22", 2);
  quic_qpack_dyn_init(&t, 4096);
  quic_qpack_dyn_insert(&t, &a);
  quic_qpack_dyn_insert(&t, &b);
  quic_qpack_field e;
  CHECK(quic_qpack_dyn_get(&t, 1, &e) == 1);
  CHECK(e.name.n == 2 && e.name.p[0] == 'b' && e.name.p[1] == 'b');
  CHECK(e.value.n == 2 && e.value.p[0] == '2' && e.value.p[1] == '2');
}

/* RFC 9204 3.2.4: an evicted absolute index is no longer resolvable. */
static void test_get_evicted(void) {
  quic_qpack_dyn   t;
  quic_qpack_field a = dg_field("a", 1, "1", 1);
  quic_qpack_field b = dg_field("b", 1, "2", 1);
  quic_qpack_field c = dg_field("c", 1, "3", 1);
  quic_qpack_dyn_init(&t, 70);
  quic_qpack_dyn_insert(&t, &a);
  quic_qpack_dyn_insert(&t, &b);
  quic_qpack_dyn_insert(&t, &c); /* evicts abs 0 */
  quic_qpack_field e;
  CHECK(quic_qpack_dyn_get(&t, 0, &e) == 0);
  CHECK(quic_qpack_dyn_get(&t, 2, &e) == 1);
  CHECK(quic_qpack_dyn_get(&t, 3, &e) == 0); /* never inserted */
}

/* RFC 9204 3.2.5: on the encoder stream, relative index 0 is the most
 * recently inserted entry. */
static void test_get_enc_rel_most_recent(void) {
  quic_qpack_dyn   t;
  quic_qpack_field a = dg_field("a", 1, "1", 1);
  quic_qpack_field b = dg_field("bb", 2, "22", 2);
  quic_qpack_dyn_init(&t, 4096);
  quic_qpack_dyn_insert(&t, &a);
  quic_qpack_dyn_insert(&t, &b);
  quic_qpack_field e;
  CHECK(quic_qpack_dyn_get_enc_rel(&t, 0, &e) == 1);
  CHECK(e.name.n == 2 && e.name.p[0] == 'b' && e.name.p[1] == 'b');
  CHECK(quic_qpack_dyn_get_enc_rel(&t, 1, &e) == 1);
  CHECK(e.name.n == 1 && e.name.p[0] == 'a');
}

/* RFC 9204 2.2.3: an encoder-stream relative index resolving to an already
 * evicted entry fails -- the caller treats this as a connection error of
 * type QPACK_ENCODER_STREAM_ERROR. */
static void test_get_enc_rel_evicted(void) {
  quic_qpack_dyn   t;
  quic_qpack_field a = dg_field("a", 1, "1", 1);
  quic_qpack_field b = dg_field("b", 1, "2", 1);
  quic_qpack_field c = dg_field("c", 1, "3", 1);
  quic_qpack_dyn_init(&t, 70);
  quic_qpack_dyn_insert(&t, &a);
  quic_qpack_dyn_insert(&t, &b);
  quic_qpack_dyn_insert(&t, &c); /* evicts abs 0 ("a") */
  quic_qpack_field e;
  /* base is now 3 (dropped 1, count 2): rel 1 -> abs 1 ("b"), still live. */
  CHECK(quic_qpack_dyn_get_enc_rel(&t, 1, &e) == 1);
  /* rel 2 -> abs 0 ("a"), evicted. */
  CHECK(quic_qpack_dyn_get_enc_rel(&t, 2, &e) == 0);
  /* an out-of-range relative index (underflows past 0) also fails. */
  CHECK(quic_qpack_dyn_get_enc_rel(&t, 99, &e) == 0);
}

void test_dynget(void) {
  test_get_live();
  test_get_evicted();
  test_get_enc_rel_most_recent();
  test_get_enc_rel_evicted();
}
