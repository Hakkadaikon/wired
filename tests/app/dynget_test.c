#include "app/qpack/qpack/dynget.h"

#include "test.h"

/* RFC 9204 3.2.4: a live absolute index resolves to its entry. */
static void test_get_live(void) {
  quic_qpack_dyn t;
  quic_qpack_dyn_init(&t, 4096);
  quic_qpack_dyn_insert(&t, (const u8 *)"a", 1, (const u8 *)"1", 1);
  quic_qpack_dyn_insert(&t, (const u8 *)"bb", 2, (const u8 *)"22", 2);
  const u8 *n, *v;
  usz       nl, vl;
  CHECK(quic_qpack_dyn_get(&t, 1, &n, &nl, &v, &vl) == 1);
  CHECK(nl == 2 && n[0] == 'b' && n[1] == 'b');
  CHECK(vl == 2 && v[0] == '2' && v[1] == '2');
}

/* RFC 9204 3.2.4: an evicted absolute index is no longer resolvable. */
static void test_get_evicted(void) {
  quic_qpack_dyn t;
  quic_qpack_dyn_init(&t, 70);
  quic_qpack_dyn_insert(&t, (const u8 *)"a", 1, (const u8 *)"1", 1);
  quic_qpack_dyn_insert(&t, (const u8 *)"b", 1, (const u8 *)"2", 1);
  quic_qpack_dyn_insert(
      &t, (const u8 *)"c", 1, (const u8 *)"3", 1); /* evicts abs 0 */
  const u8 *n, *v;
  usz       nl, vl;
  CHECK(quic_qpack_dyn_get(&t, 0, &n, &nl, &v, &vl) == 0);
  CHECK(quic_qpack_dyn_get(&t, 2, &n, &nl, &v, &vl) == 1);
  CHECK(quic_qpack_dyn_get(&t, 3, &n, &nl, &v, &vl) == 0); /* never inserted */
}

void test_dynget(void) {
  test_get_live();
  test_get_evicted();
}
