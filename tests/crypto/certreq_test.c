#include "test.h"

static void test_certreq_wire_structure(void) {
  u8         sa[4] = {0x04, 0x03, 0x08, 0x04};
  u8         out[64];
  wired_obuf o = obuf_of(out, sizeof(out));
  CHECK(certreq_build(wired_span_of(sa, sizeof(sa)), &o) == 1);
  /* handshake type 0x0d, then 24-bit body length. RFC 8446 4.3.2. */
  CHECK(out[0] == 0x0d);
  CHECK(((usz)out[1] << 16 | (usz)out[2] << 8 | out[3]) == o.len - 4);
  /* empty certificate_request_context. */
  CHECK(out[4] == 0);
  /* extensions block length covers a single signature_algorithms extension:
   * type(2) extlen(2) listlen(2) + 4 schemes = 10 bytes. */
  CHECK(((usz)out[5] << 8 | out[6]) == 10);
  CHECK(((u16)out[7] << 8 | out[8]) == 0x000d); /* signature_algorithms */
  CHECK(((u16)out[11] << 8 | out[12]) == 4);    /* scheme list length */
  CHECK(out[13] == 0x04 && out[14] == 0x03);
}

static void test_certreq_build_no_room(void) {
  u8         sa[4] = {0x04, 0x03, 0x08, 0x04};
  u8         out[8];
  wired_obuf o = obuf_of(out, sizeof(out));
  CHECK(certreq_build(wired_span_of(sa, sizeof(sa)), &o) == 0);
}

void test_certreq(void) {
  test_certreq_wire_structure();
  test_certreq_build_no_room();
}
