#include "test.h"

/* RFC 9000 12.4: frames concatenate in order; cap overflow yields 0. */
void test_framepack(void) {
  u8        f0[]     = {0x00};             /* PADDING */
  u8        f1[]     = {0x01};             /* PING */
  u8        f2[]     = {0x02, 0xAA, 0xBB}; /* ACK-ish blob */
  const u8 *frames[] = {f0, f1, f2};
  const usz lens[]   = {1, 1, 3};

  u8  out[16];
  usz n = 999;
  CHECK(quic_pktbuild_framepack(out, sizeof(out), frames, lens, 3, &n) == 1);
  CHECK(n == 5);
  CHECK(out[0] == 0x00 && out[1] == 0x01);
  CHECK(out[2] == 0x02 && out[3] == 0xAA && out[4] == 0xBB);

  /* cap overflow: writes nothing, returns 0 */
  u8  tiny[4];
  usz m = 7;
  CHECK(quic_pktbuild_framepack(tiny, sizeof(tiny), frames, lens, 3, &m) == 0);

  /* zero frames -> empty payload */
  usz z = 9;
  CHECK(quic_pktbuild_framepack(out, sizeof(out), frames, lens, 0, &z) == 1);
  CHECK(z == 0);
}
