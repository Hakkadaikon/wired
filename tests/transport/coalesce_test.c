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

  coalesce_iter it;
  coalesced     p;
  coalesce_begin(&it, dg, n);

  CHECK(coalesce_next(&it, &p) == 1);
  CHECK(p.len == initial_len && p.data[0] == 0xC0);

  CHECK(coalesce_next(&it, &p) == 1);
  CHECK(p.len == 4 && p.data[0] == 0x40); /* short runs to the end */

  CHECK(coalesce_next(&it, &p) == 0); /* exhausted */
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

  coalesce_iter it;
  coalesced     p;
  coalesce_begin(&it, dg, n);
  CHECK(coalesce_next(&it, &p) == 0);
}

/* Run coalesce_next over the first n bytes of dg (a single packet). */
static int coalesce_test_first(const u8* dg, usz n) {
  coalesce_iter it;
  coalesced     p;
  coalesce_begin(&it, dg, n);
  return coalesce_next(&it, &p);
}

/* RFC 9000 17.2: a long header cut before its Version ends, before a CID
 * length byte, inside the Initial Token Length varint, or before the Length
 * field is malformed and yields no packet. */
static void test_coalesce_cut_prefix_rejected(void) {
  /* v1 Initial: DCID 0, SCID 0, Token Length 0x40.. (2-byte, cut) */
  const u8 ini[] = {0xC0, 0, 0, 0, 1, 0, 0, 0x40};
  /* v1 Handshake: DCID 0, SCID 0, then no Length field */
  const u8 hs[] = {0xE0, 0, 0, 0, 1, 0, 0};
  CHECK(coalesce_test_first(ini, 4) == 0);           /* Version cut */
  CHECK(coalesce_test_first(ini, 5) == 0);           /* no DCID length */
  CHECK(coalesce_test_first(ini, sizeof(ini)) == 0); /* token len cut */
  CHECK(coalesce_test_first(hs, sizeof(hs)) == 0);   /* no Length */
}

void test_coalesce(void) {
  test_coalesce_cut_prefix_rejected();
  test_coalesce_split();
  test_coalesce_truncated();
}
