#include "test.h"

/* A datagram with an Initial packet then a short-header packet splits into
 * two, the Initial bounded by its Length field and the short running to the
 * end. */
static void test_coalesce_split(void) {
  /* Initial: byte0=0xC0, version=1, DCID len 0, SCID len 0, token len 0,
   * Length=3, 3-byte payload. Header before payload is 11 bytes. */
  u8  dg[32];
  usz n           = 0;
  dg[n++]         = 0xC0;
  dg[n++]         = 0;
  dg[n++]         = 0;
  dg[n++]         = 0;
  dg[n++]         = 1; /* version 1 */
  dg[n++]         = 0; /* DCID len */
  dg[n++]         = 0; /* SCID len */
  dg[n++]         = 0; /* token len (varint 0) */
  dg[n++]         = 3; /* Length (varint 3) */
  dg[n++]         = 0xAA;
  dg[n++]         = 0xBB;
  dg[n++]         = 0xCC; /* payload */
  usz initial_len = n;    /* should be 11 */
  /* short-header packet: byte0=0x40 + 3 bytes */
  dg[n++] = 0x40;
  dg[n++] = 1;
  dg[n++] = 2;
  dg[n++] = 3;

  quic_coalesce_iter it;
  quic_coalesced     p;
  quic_coalesce_begin(&it, dg, n);

  CHECK(quic_coalesce_next(&it, &p) == 1);
  CHECK(p.len == initial_len && p.data[0] == 0xC0);

  CHECK(quic_coalesce_next(&it, &p) == 1);
  CHECK(p.len == 4 && p.data[0] == 0x40); /* short runs to the end */

  CHECK(quic_coalesce_next(&it, &p) == 0); /* exhausted */
}

/* A long header whose Length runs past the datagram is malformed. */
static void test_coalesce_truncated(void) {
  u8  dg[16];
  usz n   = 0;
  dg[n++] = 0xC0;
  dg[n++] = 0;
  dg[n++] = 0;
  dg[n++] = 0;
  dg[n++] = 1;
  dg[n++] = 0;
  dg[n++] = 0;
  dg[n++] = 0;  /* DCID/SCID/token lens */
  dg[n++] = 20; /* Length 20 but only a few bytes follow */
  dg[n++] = 0xAA;

  quic_coalesce_iter it;
  quic_coalesced     p;
  quic_coalesce_begin(&it, dg, n);
  CHECK(quic_coalesce_next(&it, &p) == 0);
}

void test_coalesce(void) {
  test_coalesce_split();
  test_coalesce_truncated();
}
