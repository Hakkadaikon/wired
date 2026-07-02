#include "app/qpack/qpackdyn/field_encode.h"
#include "test.h"

/* RFC 9204 4.5.2: dynamic Indexed Field Line (T=0), relative index 5 is
 * 10000101 = 0x85. */
static void test_indexed_dynamic_golden(void) {
  u8        out[4];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  usz       w  = quic_qdyn_indexed_dynamic(5, &ob);
  CHECK(w == ob.len && ob.len == 1 && out[0] == 0x85);
}

/* Relative index 63 fills the 6-bit prefix, spilling to 0xBF 0x00. */
static void test_indexed_dynamic_prefix_boundary(void) {
  u8        out[4];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  usz       w  = quic_qdyn_indexed_dynamic(63, &ob);
  CHECK(w == ob.len && ob.len == 2 && out[0] == 0xBF && out[1] == 0x00);
}

void test_qpackdyn_field_encode(void) {
  test_indexed_dynamic_golden();
  test_indexed_dynamic_prefix_boundary();
}
