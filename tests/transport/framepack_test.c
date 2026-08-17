#include "test.h"

/* RFC 9000 12.4: frames concatenate in order; cap overflow yields 0. */
void test_framepack(void) {
  u8         f0[] = {0x00};             /* PADDING */
  u8         f1[] = {0x01};             /* PING */
  u8         f2[] = {0x02, 0xAA, 0xBB}; /* ACK-ish blob */
  wired_span frames[3];
  frames[0] = wired_span_of(f0, 1);
  frames[1] = wired_span_of(f1, 1);
  frames[2] = wired_span_of(f2, 3);

  u8         out[16];
  wired_obuf o = obuf_of(out, sizeof(out));
  CHECK(pktbuild_framepack(&o, frames, 3) == 1);
  CHECK(o.len == 5);
  CHECK(out[0] == 0x00 && out[1] == 0x01);
  CHECK(out[2] == 0x02 && out[3] == 0xAA && out[4] == 0xBB);

  /* cap overflow: returns 0 */
  u8         tiny[4];
  wired_obuf t = obuf_of(tiny, sizeof(tiny));
  CHECK(pktbuild_framepack(&t, frames, 3) == 0);

  /* zero frames -> empty payload */
  wired_obuf z = obuf_of(out, sizeof(out));
  CHECK(pktbuild_framepack(&z, frames, 0) == 1);
  CHECK(z.len == 0);
}
